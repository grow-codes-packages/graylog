"""Log query clients for Graylog (views search, polling tail, streams, fields)."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from ._core import ValidationError
from ._core.env import to_seconds
from ._logging import (
    AsyncBaseLogQueryClient,
    AsyncPollingTail,
    AsyncTailHandle,
    BaseLogQueryClient,
    LogRecord,
    LogSearchResult,
    PollingTail,
    SearchOrder,
    TailHandle,
)
from .gelf import log_record_from_message
from .models import SearchResult, SearchSort

if TYPE_CHECKING:
    from .client import AsyncGraylogClient, GraylogClient

__all__ = [
    "DEFAULT_TAIL_INTERVAL_S",
    "AsyncGraylogLogQueryClient",
    "GraylogLogQueryClient",
]

#: Default poll interval of ``tail`` (decision 1: Graylog has no streaming API).
DEFAULT_TAIL_INTERVAL_S = 2.0
#: Default search window when ``start`` is not given: ``end`` minus one hour.
DEFAULT_WINDOW_S = 3600.0


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
    streaming API: :meth:`tail` polls every 2 s.

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
        interval_s: float = DEFAULT_TAIL_INTERVAL_S,
        on_error: Callable[[Exception], None] | None = None,
    ) -> TailHandle:
        """Poll for new matching records every ``interval_s`` (default 2 s) on a thread."""
        return PollingTail(
            self,
            query,
            on_record,
            interval_s=interval_s,
            start=datetime.now(timezone.utc),
            on_error=on_error,
        )

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
        interval_s: float = DEFAULT_TAIL_INTERVAL_S,
        on_error: Callable[[Exception], None] | None = None,
    ) -> AsyncTailHandle:
        """Poll for new matching records every ``interval_s`` (default 2 s) on the loop."""
        return AsyncPollingTail(
            self,
            query,
            on_record,
            interval_s=interval_s,
            start=datetime.now(timezone.utc),
            on_error=on_error,
        )

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
