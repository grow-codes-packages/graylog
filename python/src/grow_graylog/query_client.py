"""Log query clients for Graylog (views search, polling tail, streams, fields)."""

from __future__ import annotations

import asyncio
import contextlib
import threading
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from ._core import CancelledError, ValidationError
from ._core.env import to_seconds
from ._logging import (
    AsyncBaseLogQueryClient,
    BaseLogQueryClient,
    LogRecord,
    LogSearchResult,
    SearchOrder,
)
from .gelf import log_record_from_message
from .models import GraylogMessage, SearchResult, SearchSort

if TYPE_CHECKING:
    from .client import AsyncGraylogClient, GraylogClient

__all__ = [
    "DEFAULT_TAIL_INTERVAL_S",
    "TAIL_OVERLAP_S",
    "AsyncGraylogLogQueryClient",
    "AsyncGraylogTail",
    "GraylogLogQueryClient",
    "GraylogTail",
]

#: Default poll interval of ``tail`` (decision 1: Graylog has no streaming API).
DEFAULT_TAIL_INTERVAL_S = 2.0
#: Default search window when ``start`` is not given: ``end`` minus one hour.
DEFAULT_WINDOW_S = 3600.0
#: How far back each tail poll looks before the newest record seen, so records that become
#: searchable late (ingest takes 1-2 s) are not missed; duplicates are dropped by message id.
TAIL_OVERLAP_S = 10.0

_TAIL_SORT = [SearchSort("timestamp", "asc"), SearchSort("gl2_message_id", "asc")]


class _TailWindow:
    """What a tail has delivered: the start, the newest timestamp and recent message ids."""

    def __init__(self, since: datetime) -> None:
        self.since = since
        self.newest: datetime | None = None
        self.seen: dict[str, datetime] = {}

    def start(self) -> datetime:
        if self.newest is None:
            return self.since
        return max(self.since, self.newest - timedelta(seconds=TAIL_OVERLAP_S))

    def fresh(self, messages: list[GraylogMessage]) -> list[LogRecord]:
        out: list[LogRecord] = []
        for m in messages:
            if m.id and m.id in self.seen:
                continue
            ts = m.timestamp or self.since
            self.seen[m.id] = ts
            if self.newest is None or ts > self.newest:
                self.newest = ts
            out.append(log_record_from_message(m.fields))
        return out

    def forget(self) -> None:
        """Forget ids that can no longer appear in a window."""
        if self.newest is not None:
            cutoff = self.newest - timedelta(seconds=2 * TAIL_OVERLAP_S)
            self.seen = {k: v for k, v in self.seen.items() if v >= cutoff}


def _tail_interval(interval_s: float | timedelta) -> float:
    interval = to_seconds(interval_s)
    return interval if interval > 0 else DEFAULT_TAIL_INTERVAL_S


class GraylogTail:
    """Polling tail of :meth:`GraylogLogQueryClient.tail` (a daemon thread).

    :meth:`stop` is idempotent; closing the client stops the tail too.
    """

    def __init__(
        self,
        query_client: GraylogLogQueryClient,
        query: str,
        on_record: Callable[[LogRecord], None],
        *,
        interval_s: float | timedelta,
        start: datetime,
        on_error: Callable[[Exception], None] | None,
    ) -> None:
        self._query_client = query_client
        self._query = query
        self._on_record = on_record
        self._on_error = on_error
        self._interval = _tail_interval(interval_s)
        self._window = _TailWindow(start)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="grow-graylog-tail", daemon=True)
        self._thread.start()

    def poll_once(self) -> int:
        """Run one poll; returns the number of delivered records."""
        client = self._query_client._client
        delivered = 0
        offset = 0
        start = self._window.start()
        while True:
            result = client.search(
                self._query,
                from_=start,
                to=datetime.now(timezone.utc) + timedelta(minutes=1),
                limit=1000,
                offset=offset,
                sort=_TAIL_SORT,
                streams=self._query_client.streams,
            )
            for record in self._window.fresh(result.messages):
                if self._stop.is_set():
                    return delivered
                with contextlib.suppress(Exception):  # a failing callback must not stop the tail
                    self._on_record(record)
                delivered += 1
            offset += len(result.messages)
            if not result.messages or offset >= result.total:
                break
        self._window.forget()
        return delivered

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as exc:  # noqa: BLE001 - reported to on_error, polling continues
                if self._on_error is not None and not self._stop.is_set():
                    self._on_error(exc)
            self._stop.wait(self._interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not threading.current_thread():
            self._thread.join()


class AsyncGraylogTail:
    """Polling tail of :meth:`AsyncGraylogLogQueryClient.tail` (a task on the running loop).

    :meth:`stop` is idempotent; closing the client stops the tail too.
    """

    def __init__(
        self,
        query_client: AsyncGraylogLogQueryClient,
        query: str,
        on_record: Callable[[LogRecord], None],
        *,
        interval_s: float | timedelta,
        start: datetime,
        on_error: Callable[[Exception], None] | None,
    ) -> None:
        self._query_client = query_client
        self._query = query
        self._on_record = on_record
        self._on_error = on_error
        self._interval = _tail_interval(interval_s)
        self._window = _TailWindow(start)
        self._task = asyncio.get_running_loop().create_task(self._run())

    async def poll_once(self) -> int:
        """Run one poll; returns the number of delivered records."""
        client = self._query_client._client
        delivered = 0
        offset = 0
        start = self._window.start()
        while True:
            result = await client.search(
                self._query,
                from_=start,
                to=datetime.now(timezone.utc) + timedelta(minutes=1),
                limit=1000,
                offset=offset,
                sort=_TAIL_SORT,
                streams=self._query_client.streams,
            )
            for record in self._window.fresh(result.messages):
                with contextlib.suppress(Exception):  # a failing callback must not stop the tail
                    self._on_record(record)
                delivered += 1
            offset += len(result.messages)
            if not result.messages or offset >= result.total:
                break
        self._window.forget()
        return delivered

    async def _run(self) -> None:
        while True:
            try:
                await self.poll_once()
            except Exception as exc:  # noqa: BLE001 - reported to on_error, polling continues
                if self._on_error is not None:
                    self._on_error(exc)
            await asyncio.sleep(self._interval)

    def cancel(self) -> None:
        """Stop without waiting (used by ``client.close()``)."""
        self._task.cancel()

    async def stop(self) -> None:
        if not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task


class _QueryBase:
    def __init__(self, streams: Sequence[str] | None, default_window_s: float | timedelta) -> None:
        self.streams = list(streams) if streams is not None else None
        self.default_window_s = to_seconds(default_window_s)
        if not self.default_window_s > 0:
            raise ValidationError("log_query_client: default_window_s must be positive")

    def _args(
        self,
        start: datetime | None,
        end: datetime | None,
        order: SearchOrder,
        cursor: str | None,
    ) -> tuple[datetime, datetime, int, list[SearchSort]]:
        until = end or datetime.now(timezone.utc)
        since = start or until - timedelta(seconds=self.default_window_s)
        offset = 0
        if cursor is not None:
            if not cursor.isdigit() or not cursor.isascii():
                raise ValidationError("logging.search: invalid cursor")
            offset = int(cursor)
        sort = [SearchSort("timestamp", order), SearchSort("gl2_message_id", order)]
        return since, until, offset, sort

    @staticmethod
    def _result(result: SearchResult) -> LogSearchResult:
        return LogSearchResult(
            records=[log_record_from_message(m.fields) for m in result.messages],
            next_cursor=str(result.next_offset) if result.next_offset is not None else None,
            total=result.total,
        )


class GraylogLogQueryClient(_QueryBase, BaseLogQueryClient):
    """``LogQueryClient`` on top of :meth:`GraylogClient.search`.

    Absolute time range (default: the last hour), timestamp order (ties broken by
    ``gl2_message_id``), offset cursors, hits normalised into log records. Graylog has no
    streaming API: :meth:`tail` polls every 2 s with a 10 s look-back window.

    Args:
        client: the Graylog client.
        streams: stream ids every search is limited to (default: every readable stream).
        default_window_s: search window when ``start`` is not given (default 3600 s).
    """

    def __init__(
        self,
        client: GraylogClient,
        *,
        streams: Sequence[str] | None = None,
        default_window_s: float | timedelta = DEFAULT_WINDOW_S,
    ) -> None:
        super().__init__(streams, default_window_s)
        self._client = client

    def search(
        self,
        query: str,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 100,
        order: SearchOrder = "desc",
        cursor: str | None = None,
    ) -> LogSearchResult:
        """Search records; ``cursor`` is the offset of the next page."""
        since, until, offset, sort = self._args(start, end, order, cursor)
        result = self._client.search(
            query,
            from_=since,
            to=until,
            limit=limit,
            offset=offset,
            sort=sort,
            streams=self.streams,
        )
        return self._result(result)

    def tail(
        self,
        query: str,
        on_record: Callable[[LogRecord], None],
        *,
        interval_s: float | timedelta = DEFAULT_TAIL_INTERVAL_S,
        start: datetime | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> GraylogTail:
        """Poll for new matching records every ``interval_s`` (default 2 s) on a thread.

        Delivers each record once, oldest first, starting at ``start`` (default now). Each poll
        looks back :data:`TAIL_OVERLAP_S` before the newest record seen and drops duplicates by
        message id, so late records are delivered too. Search errors go to ``on_error`` and
        polling continues. Raises :class:`CancelledError` on a closed client.
        """
        if self._client._closed:
            raise CancelledError("logs.tail: client is closed")
        tail = GraylogTail(
            self,
            query,
            on_record,
            interval_s=interval_s,
            start=start or datetime.now(timezone.utc),
            on_error=on_error,
        )
        self._client.resources.register(tail)
        return tail

    def list_streams(self) -> list[str]:
        """Titles of every stream (all pages)."""
        titles: list[str] = []
        page = 1
        while True:
            result = self._client.list_streams(page=page, per_page=100)
            titles.extend(s.title for s in result.streams)
            if not result.streams or len(titles) >= result.total:
                return titles
            page += 1

    def list_labels(self) -> list[str]:
        """Every indexed field name."""
        return self._client.list_fields()


class AsyncGraylogLogQueryClient(_QueryBase, AsyncBaseLogQueryClient):
    """Async :class:`GraylogLogQueryClient` on top of :class:`AsyncGraylogClient`."""

    def __init__(
        self,
        client: AsyncGraylogClient,
        *,
        streams: Sequence[str] | None = None,
        default_window_s: float | timedelta = DEFAULT_WINDOW_S,
    ) -> None:
        super().__init__(streams, default_window_s)
        self._client = client

    async def search(
        self,
        query: str,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 100,
        order: SearchOrder = "desc",
        cursor: str | None = None,
    ) -> LogSearchResult:
        """Search records; ``cursor`` is the offset of the next page."""
        since, until, offset, sort = self._args(start, end, order, cursor)
        result = await self._client.search(
            query,
            from_=since,
            to=until,
            limit=limit,
            offset=offset,
            sort=sort,
            streams=self.streams,
        )
        return self._result(result)

    async def tail(
        self,
        query: str,
        on_record: Callable[[LogRecord], None],
        *,
        interval_s: float | timedelta = DEFAULT_TAIL_INTERVAL_S,
        start: datetime | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> AsyncGraylogTail:
        """Poll for new matching records every ``interval_s`` (default 2 s) on the loop.

        Same behaviour as :meth:`GraylogLogQueryClient.tail`.
        """
        if self._client._closed:
            raise CancelledError("logs.tail: client is closed")
        tail = AsyncGraylogTail(
            self,
            query,
            on_record,
            interval_s=interval_s,
            start=start or datetime.now(timezone.utc),
            on_error=on_error,
        )
        self._client.resources.register(_Canceller(tail))
        return tail

    async def list_streams(self) -> list[str]:
        """Titles of every stream (all pages)."""
        titles: list[str] = []
        page = 1
        while True:
            result = await self._client.list_streams(page=page, per_page=100)
            titles.extend(s.title for s in result.streams)
            if not result.streams or len(titles) >= result.total:
                return titles
            page += 1

    async def list_labels(self) -> list[str]:
        """Every indexed field name."""
        return await self._client.list_fields()


class _Canceller:
    """Adapts :class:`AsyncGraylogTail` to the synchronous ``ResourceRegistry``."""

    def __init__(self, tail: AsyncGraylogTail) -> None:
        self._tail = tail

    def stop(self) -> None:
        self._tail.cancel()
