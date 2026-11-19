"""Graylog Open clients (sync and async): health, REST admin (inputs, streams, index sets),
search, and log clients that send through GELF (UDP, TCP, HTTP) or OTLP/gRPC.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import time
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from types import TracebackType
from typing import Any, Literal
from urllib.parse import quote

import httpx

from ._core import (
    AsyncHttpTransport,
    CancelledError,
    CancelToken,
    ConfigError,
    ConflictError,
    HealthStatus,
    HttpTransport,
    Request,
    ResourceRegistry,
    Response,
    ServiceError,
    TimeoutError,
    TlsConfig,
    UnavailableError,
    UnsupportedError,
    ValidationError,
    apoll_until,
    poll_until,
    redact_text,
)
from ._logging import (
    AsyncBatchingLogClient,
    AttrValue,
    BatchingLogClient,
    BatchOptions,
    LogExporter,
    RedactionProcessor,
)
from .config import GelfProtocol, GraylogConfig
from .gelf_transports import (
    GelfCompression,
    GelfHttpTransport,
    GelfLogExporter,
    GelfTcpTransport,
    GelfTransport,
    GelfUdpTransport,
    ThreadedAsyncLogExporter,
)
from .models import (
    GELF_INPUT_TYPES,
    EnsuredInput,
    GraylogInput,
    GraylogMessage,
    GraylogStream,
    IndexSet,
    InputState,
    SearchResult,
    SearchSort,
    StreamPage,
    StreamRule,
    SystemInfo,
    decode_index_set,
    decode_input,
    decode_input_state,
    decode_message,
    decode_search,
    decode_stream,
    decode_stream_page,
    decode_system_info,
    ensured_input,
    expect_object,
)
from .otlp import OtlpGrpcLogExporter
from .query_client import AsyncGraylogLogQueryClient, GraylogLogQueryClient

__all__ = ["AsyncGraylogClient", "GraylogClient", "LogProtocol"]

LogProtocol = Literal["udp", "tcp", "http", "otlp"]
"""Transport of :meth:`GraylogClient.log_client`: a GELF protocol or ``otlp`` (gRPC)."""

_UNSET: Any = object()
_HEALTH = Request(
    "GET",
    "/api/system/lbstatus",
    operation="health",
    headers={"Accept": "text/plain"},
    raise_for_status=False,
    max_retries=0,
)
_DEFAULT_SEARCH_WINDOW_S = 300
_MAX_INT = 2**53 - 1


# --------------------------------------------------------------------------- helpers


def _seg(value: str, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{what} must not be empty")
    return quote(value, safe="")


def _check_int(value: int | None, name: str, low: int, high: int) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValidationError(f"{name} must be an integer {low}..{high}")


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    utc = value.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def _gelf_input_configuration(protocol: str, port: int, bind_address: str) -> dict[str, Any]:
    common: dict[str, Any] = {
        "bind_address": bind_address,
        "port": port,
        "number_worker_threads": 2,
        "decompress_size_limit": 8_388_608,
    }
    if protocol == "udp":
        return {**common, "recv_buffer_size": 262_144}
    if protocol == "tcp":
        return {
            **common,
            "recv_buffer_size": 1_048_576,
            "tls_enable": False,
            "tcp_keepalive": False,
            "use_null_delimiter": True,
            "max_message_size": 2_097_152,
        }
    return {
        **common,
        "recv_buffer_size": 1_048_576,
        "tls_enable": False,
        "tcp_keepalive": False,
        "enable_bulk_receiving": True,
        "enable_cors": True,
        "max_chunk_size": 8_388_608,
        "idle_writer_timeout": 60,
    }


def _health_from_response(resp: Response) -> HealthStatus:
    if resp.status == 429:
        return HealthStatus(False, "degraded", {"lb_status": "THROTTLED"})
    if resp.status == 503:
        return HealthStatus(False, "unhealthy", {"lb_status": "DEAD"})
    word = resp.text.strip().upper()
    if resp.ok and word == "ALIVE":
        return HealthStatus(True, "ok", {"lb_status": word})
    details = {"lb_status": word} if resp.ok else {"httpStatus": str(resp.status)}
    return HealthStatus(False, "unhealthy", details)


def _health_from_error(err: ServiceError) -> HealthStatus:
    if isinstance(err, (CancelledError, ConfigError)):
        raise err
    word = "unreachable" if isinstance(err, (UnavailableError, TimeoutError)) else "unhealthy"
    return HealthStatus(healthy=False, status=word, details={"error": err.message})


def _version(info: SystemInfo) -> str:
    if not info.version:
        raise UnsupportedError("server_version: the service does not report a version")
    return info.version


def _timerange(
    range_s: int | None,
    from_: datetime | None,
    to: datetime | None,
    keyword: str | None,
) -> dict[str, Any]:
    kinds = (range_s is not None) + (from_ is not None or to is not None) + (keyword is not None)
    if kinds > 1:
        raise ValidationError("search: give only one of range_s, from_/to and keyword")
    if from_ is not None or to is not None:
        until = to or datetime.now(timezone.utc)
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        since = from_ or until - timedelta(seconds=_DEFAULT_SEARCH_WINDOW_S)
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        if since > until:
            raise ValidationError("search: from_ is after to")
        return {"type": "absolute", "from": _iso(since), "to": _iso(until)}
    if keyword is not None:
        if not keyword.strip():
            raise ValidationError("search: keyword must not be empty")
        return {"type": "keyword", "keyword": keyword}
    rng = _DEFAULT_SEARCH_WINDOW_S if range_s is None else range_s
    _check_int(rng, "search: range_s (seconds)", 1, _MAX_INT)
    return {"type": "relative", "range": rng}


def _search_request(
    query: str,
    *,
    range_s: int | None,
    from_: datetime | None,
    to: datetime | None,
    keyword: str | None,
    limit: int,
    offset: int,
    fields: Sequence[str] | None,
    sort: SearchSort | Sequence[SearchSort] | None,
    streams: Sequence[str] | None,
) -> Request:
    timerange = _timerange(range_s, from_, to, keyword)
    _check_int(limit, "search: limit", 1, 10_000)
    _check_int(offset, "search: offset", 0, _MAX_INT)
    if sort is None:
        sorts: list[SearchSort] = [SearchSort("timestamp", "desc")]
    elif isinstance(sort, SearchSort):
        sorts = [sort]
    else:
        sorts = list(sort)
    search_type: dict[str, Any] = {
        "id": "st1",
        "type": "messages",
        "limit": limit,
        "offset": offset,
        "sort": [{"field": s.field, "order": s.order.upper()} for s in sorts],
    }
    if fields:
        search_type["fields"] = list(fields)
    q: dict[str, Any] = {
        "id": "q1",
        "query": {
            "type": "elasticsearch",
            "query_string": query if isinstance(query, str) and query.strip() else "*",
        },
        "timerange": timerange,
        "search_types": [search_type],
    }
    if streams:
        q["filter"] = {"type": "or", "filters": [{"type": "stream", "id": s} for s in streams]}
    return Request(
        "POST",
        "/api/views/search/sync",
        operation="search",
        json={"queries": [q]},
        idempotent=True,
    )


def _create_input_request(
    input_type: str,
    configuration: Mapping[str, Any],
    title: str | None,
    global_: bool,
    node: str | None,
) -> Request:
    if not isinstance(input_type, str) or not input_type.strip():
        raise ValidationError("create_input: input_type must not be empty")
    short = input_type.rsplit(".", 1)[-1]
    body: dict[str, Any] = {
        "title": title or f"{short} (grow-codes)",
        "type": input_type,
        "global": global_,
        "configuration": dict(configuration),
    }
    if node is not None:
        body["node"] = node
    return Request("POST", "/api/system/inputs", operation="create_input", json=body)


def _created_id(resp: Response, key: str, operation: str) -> str:
    value = expect_object(resp, operation).get(key)
    if not isinstance(value, str):
        raise ValidationError(f"{operation}: response without {key}")
    return value


def _list_streams_request(
    page: int, per_page: int, query: str | None, sort: str, order: str
) -> Request:
    _check_int(page, "list_streams: page", 1, _MAX_INT)
    _check_int(per_page, "list_streams: per_page", 1, 10_000)
    return Request(
        "GET",
        "/api/streams/paginated",
        operation="list_streams",
        params={
            "page": page,
            "per_page": per_page,
            "sort": sort,
            "order": order,
            "query": query or None,
        },
    )


def _stream_entity(
    title: str,
    description: str,
    index_set_id: str,
    rules: Sequence[StreamRule],
    matching_type: str,
    remove_matches_from_default_stream: bool,
) -> dict[str, Any]:
    return {
        "entity": {
            "title": title,
            "description": description,
            "index_set_id": index_set_id,
            "matching_type": matching_type,
            "remove_matches_from_default_stream": remove_matches_from_default_stream,
            "rules": [
                {
                    "field": r.field,
                    "type": r.type,
                    "value": r.value,
                    "inverted": r.inverted,
                    "description": r.description,
                }
                for r in rules
            ],
        }
    }


def _check_title(title: str) -> None:
    if not isinstance(title, str) or not title.strip():
        raise ValidationError("create_stream: title must not be empty")


def _default_index_set(sets: list[IndexSet]) -> str:
    chosen = next((s for s in sets if s.is_default), sets[0] if sets else None)
    if chosen is None:
        raise ValidationError("create_stream: no index set available")
    return chosen.id


def _ensure_match(
    inputs: list[GraylogInput], input_type: str, port: int, bind_address: str
) -> GraylogInput | None:
    return next(
        (
            i
            for i in inputs
            if i.type == input_type
            and i.port == port
            and (i.bind_address is None or i.bind_address == bind_address)
        ),
        None,
    )


def _ensure_type(protocol: str, port: int) -> str:
    input_type = GELF_INPUT_TYPES.get(protocol)
    if input_type is None:
        raise ValidationError("ensure_gelf_input: protocol must be udp, tcp or http")
    _check_int(port, "ensure_gelf_input: port", 1, 65535)
    return input_type


def _input_state_or_none(resp: Response) -> InputState | None:
    if resp.status == 404:
        return None
    return decode_input_state(expect_object(resp, "ensure_gelf_input"))


def _state_done(state: InputState) -> bool:
    return state.state in ("RUNNING", "FAILED")


def _list_fields(resp: Response) -> list[str]:
    fields = expect_object(resp, "list_fields").get("fields")
    if not isinstance(fields, list):
        return []
    return sorted(f for f in fields if isinstance(f, str))


def _decode_get_message(resp: Response) -> GraylogMessage:
    body = expect_object(resp, "get_message")
    message = body.get("message")
    fields = message.get("fields") if isinstance(message, dict) else None
    return decode_message(fields or {}, body.get("index"))


class _ClientCore:
    """Configuration, headers and transport factories shared by both clients."""

    config: GraylogConfig

    def _setup(self, config: GraylogConfig | None) -> GraylogConfig:
        if config is None:
            config = GraylogConfig.from_env()
        self.config = config.validate()
        self._resources = ResourceRegistry()
        auth = self.config.authorization_header()
        headers = {"X-Requested-By": self.config.requested_by}
        if auth is not None:
            headers["Authorization"] = auth
        return dataclasses.replace(self.config, headers={**headers, **self.config.headers})

    @property
    def resources(self) -> ResourceRegistry:
        """Background resources stopped by ``close``."""
        return self._resources

    def _redact(self, text: str) -> str:
        return redact_text(text, self.config.known_secrets())

    def _decode_search(self, resp: Response, offset: int) -> SearchResult:
        return decode_search(expect_object(resp, "search"), offset, self._redact)

    def _failed_input(self, protocol: str, port: int, state: InputState) -> ConflictError:
        detail = f": {self._redact(state.detailed_message)[:300]}" if state.detailed_message else ""
        return ConflictError(f"ensure_gelf_input {protocol}:{port}: input failed to start{detail}")

    def gelf_transport(
        self,
        protocol: GelfProtocol | None = None,
        *,
        compression: GelfCompression | None = None,
        chunk_size: int | None = None,
        bulk: bool | None = None,
        headers: Mapping[str, str] | None = None,
        http_transport: httpx.BaseTransport | None = None,
    ) -> GelfTransport:
        """Build a GELF transport from the configuration (default ``config.gelf_protocol``).

        ``compression`` and ``chunk_size`` apply to UDP; ``bulk`` and ``headers`` to HTTP.
        """
        cfg = self.config
        proto = protocol or cfg.gelf_protocol
        if proto == "udp":
            udp_kw: dict[str, Any] = {}
            if compression is not None:
                udp_kw["compression"] = compression
            if chunk_size is not None:
                udp_kw["chunk_size"] = chunk_size
            return GelfUdpTransport(cfg.gelf_host, cfg.gelf_port_for("udp"), **udp_kw)
        if proto == "tcp":
            tls: bool | TlsConfig = cfg.tls if cfg.gelf_tls else False
            return GelfTcpTransport(
                cfg.gelf_host,
                cfg.gelf_port_for("tcp"),
                tls=tls,
                connect_timeout_s=cfg.connect_timeout,
                write_timeout_s=cfg.request_timeout,
                retry=cfg.retry,
            )
        if proto == "http":
            return GelfHttpTransport(
                cfg.gelf_http_endpoint(),
                bulk=True if bulk is None else bulk,
                headers=headers,
                config=cfg,
                http_transport=http_transport,
            )
        raise ValidationError("gelf_transport: protocol must be udp, tcp or http")

    def _exporter(
        self,
        protocol: LogProtocol | None,
        host: str | None,
        transport: GelfTransport | None,
        compression: GelfCompression | None,
        chunk_size: int | None,
        bulk: bool | None,
        headers: Mapping[str, str] | None,
        bearer_token: str | None,
    ) -> LogExporter:
        proto = protocol or self.config.gelf_protocol
        if proto == "otlp":
            return OtlpGrpcLogExporter(
                self.config.otlp_grpc_endpoint(),
                bearer_token=bearer_token,
                headers=headers,
                tls=self.config.tls,
                timeout_s=self.config.request_timeout,
                connect_timeout_s=self.config.connect_timeout,
            )
        gelf = transport or self.gelf_transport(
            proto, compression=compression, chunk_size=chunk_size, bulk=bulk, headers=headers
        )
        return GelfLogExporter(gelf, host=host)

    @staticmethod
    def _client_kwargs(
        options: BatchOptions | None,
        resource: Mapping[str, AttrValue] | None,
        redaction: RedactionProcessor | None,
        correlate: bool,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"options": options, "resource": resource, "correlate": correlate}
        if redaction is not _UNSET:
            kwargs["redaction"] = redaction
        return kwargs


# --------------------------------------------------------------------------- sync


class GraylogClient(_ClientCore):
    """Synchronous Graylog Open client. Thread-safe; use as a context manager or call
    :meth:`close`.

    Every REST method accepts ``cancel=`` (a :class:`CancelToken`) to abort from another thread.

    Args:
        config: the configuration (default: :meth:`GraylogConfig.from_env`).
        http_transport: test seam (an ``httpx`` transport, e.g. ``respx`` or ``MockTransport``).
    """

    def __init__(
        self,
        config: GraylogConfig | None = None,
        *,
        http_transport: httpx.BaseTransport | None = None,
    ) -> None:
        transport_config = self._setup(config)
        self._transport = HttpTransport(
            transport_config, known_secrets=self.config.known_secrets, http_transport=http_transport
        )
        self._log_clients: list[BatchingLogClient] = []
        self._closed = False

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **overrides: Any) -> GraylogClient:
        """Build a client from the ``GROW_GRAYLOG_*`` and vendor environment variables."""
        return cls(GraylogConfig.from_env(env, **overrides))

    def request(self, req: Request, *, cancel: CancelToken | None = None) -> Response:
        """Send a raw request through the client's transport (auth, retries, hooks, redaction)."""
        return self._transport.request(req, cancel=cancel)

    def _get(self, path: str, operation: str, cancel: CancelToken | None, **kw: Any) -> Response:
        return self._transport.request(
            Request("GET", path, operation=operation, **kw), cancel=cancel
        )

    # ---- client surface

    def health(self, *, cancel: CancelToken | None = None) -> HealthStatus:
        """Unauthenticated liveness: ``GET /api/system/lbstatus``.

        ``ALIVE`` → healthy ``ok``, 429 ``THROTTLED`` → ``degraded``, 503 ``DEAD`` →
        ``unhealthy``, network errors → ``unreachable``. Never raises for an unhealthy or
        unreachable service (only :class:`CancelledError` and :class:`ConfigError`).
        """
        try:
            resp = self._transport.request(_HEALTH, cancel=cancel)
        except ServiceError as err:
            return _health_from_error(err)
        return _health_from_response(resp)

    def ping(self, *, cancel: CancelToken | None = None) -> float:
        """Authenticated round trip (``GET /api/system``); returns the latency in ms."""
        started = time.monotonic()
        self._get("/api/system", "ping", cancel)
        return (time.monotonic() - started) * 1000.0

    def server_version(self, *, cancel: CancelToken | None = None) -> str:
        """Server version reported by ``GET /api/system``, e.g. ``7.0.16+58e0f6e``."""
        return _version(self.system_info(cancel=cancel))

    def system_info(self, *, cancel: CancelToken | None = None) -> SystemInfo:
        """Node and cluster information: ``GET /api/system``."""
        resp = self._get("/api/system", "system_info", cancel)
        return decode_system_info(expect_object(resp, "system_info"))

    # ---- inputs

    def list_inputs(self, *, cancel: CancelToken | None = None) -> list[GraylogInput]:
        """Every configured input: ``GET /api/system/inputs``."""
        body = expect_object(self._get("/api/system/inputs", "list_inputs", cancel), "list_inputs")
        inputs = body.get("inputs")
        return [decode_input(i) for i in inputs] if isinstance(inputs, list) else []

    def get_input(self, input_id: str, *, cancel: CancelToken | None = None) -> GraylogInput:
        """One input: ``GET /api/system/inputs/{id}``; :class:`NotFoundError` when unknown."""
        path = f"/api/system/inputs/{_seg(input_id, 'get_input: input_id')}"
        return decode_input(expect_object(self._get(path, "get_input", cancel), "get_input"))

    def get_input_state(self, input_id: str, *, cancel: CancelToken | None = None) -> InputState:
        """Runtime state of an input: ``GET /api/system/inputstates/{id}``."""
        path = f"/api/system/inputstates/{_seg(input_id, 'get_input_state: input_id')}"
        resp = self._get(path, "get_input_state", cancel)
        return decode_input_state(expect_object(resp, "get_input_state"))

    def list_input_types(self, *, cancel: CancelToken | None = None) -> dict[str, str]:
        """Installed input types, class name → human name: ``GET /api/system/inputs/types``."""
        resp = self._get("/api/system/inputs/types", "list_input_types", cancel)
        types = expect_object(resp, "list_input_types").get("types")
        return {str(k): str(v) for k, v in types.items()} if isinstance(types, dict) else {}

    def create_input(
        self,
        input_type: str,
        configuration: Mapping[str, Any],
        *,
        title: str | None = None,
        global_: bool = True,
        node: str | None = None,
        cancel: CancelToken | None = None,
    ) -> str:
        """Create an input (``POST /api/system/inputs``); returns its id.

        Unknown types raise :class:`NotFoundError`. Graylog does not reject a busy port here:
        check :meth:`get_input_state` (or use :meth:`ensure_gelf_input`).
        """
        req = _create_input_request(input_type, configuration, title, global_, node)
        return _created_id(self._transport.request(req, cancel=cancel), "id", "create_input")

    def ensure_gelf_input(
        self,
        protocol: GelfProtocol,
        port: int,
        *,
        title: str | None = None,
        bind_address: str = "0.0.0.0",  # noqa: S104 - Graylog input bind address
        configuration: Mapping[str, Any] | None = None,
        timeout_s: float | timedelta = 30.0,
        interval_s: float | timedelta = 0.5,
        cancel: CancelToken | None = None,
    ) -> EnsuredInput:
        """Return a running GELF input for ``protocol`` and ``port``, creating it when missing.

        Inputs are matched by type, port and bind address. Waits until the input is
        ``RUNNING``; a ``FAILED`` input (e.g. port in use) raises :class:`ConflictError` and an
        input created by this call is deleted again. :class:`TimeoutError` after ``timeout_s``.
        """
        input_type = _ensure_type(protocol, port)
        inp = _ensure_match(self.list_inputs(cancel=cancel), input_type, port, bind_address)
        created = False
        if inp is None:
            config = {
                **_gelf_input_configuration(protocol, port, bind_address),
                **(configuration or {}),
            }
            new_id = self.create_input(
                input_type,
                config,
                title=title or f"grow-codes GELF {protocol.upper()} {port}",
                cancel=cancel,
            )
            created = True
            inp = next(
                (i for i in self.list_inputs(cancel=cancel) if i.id == new_id), None
            ) or self.get_input(new_id, cancel=cancel)
        path = f"/api/system/inputstates/{quote(inp.id, safe='')}"
        try:
            state = poll_until(
                lambda: _input_state_or_none(
                    self._get(path, "ensure_gelf_input", cancel, raise_for_status=False)
                ),
                predicate=_state_done,
                timeout_s=_seconds(timeout_s),
                interval_s=_seconds(interval_s),
                operation=f"ensure_gelf_input {protocol}:{port}",
            )
        except TimeoutError:
            if created:
                self._delete_quietly(inp.id)
            raise
        if state.state == "FAILED":
            if created:
                self._delete_quietly(inp.id)
            raise self._failed_input(protocol, port, state)
        return ensured_input(inp, created)

    def _delete_quietly(self, input_id: str) -> None:
        with contextlib.suppress(ServiceError):
            self.delete_input(input_id)

    def delete_input(self, input_id: str, *, cancel: CancelToken | None = None) -> None:
        """Delete an input: ``DELETE /api/system/inputs/{id}``; :class:`NotFoundError`."""
        path = f"/api/system/inputs/{_seg(input_id, 'delete_input: input_id')}"
        self._transport.request(Request("DELETE", path, operation="delete_input"), cancel=cancel)

    # ---- streams and index sets

    def list_streams(
        self,
        *,
        page: int = 1,
        per_page: int = 50,
        query: str | None = None,
        sort: str = "title",
        order: Literal["asc", "desc"] = "asc",
        cancel: CancelToken | None = None,
    ) -> StreamPage:
        """One page of streams: ``GET /api/streams/paginated`` (``page`` is 1-based)."""
        req = _list_streams_request(page, per_page, query, sort, order)
        body = expect_object(self._transport.request(req, cancel=cancel), "list_streams")
        return decode_stream_page(body, page, per_page)

    def get_stream(self, stream_id: str, *, cancel: CancelToken | None = None) -> GraylogStream:
        """One stream: ``GET /api/streams/{id}``; :class:`NotFoundError` when unknown."""
        path = f"/api/streams/{_seg(stream_id, 'get_stream: stream_id')}"
        return decode_stream(expect_object(self._get(path, "get_stream", cancel), "get_stream"))

    def create_stream(
        self,
        title: str,
        *,
        description: str = "",
        index_set_id: str | None = None,
        rules: Sequence[StreamRule] = (),
        matching_type: Literal["AND", "OR"] = "AND",
        remove_matches_from_default_stream: bool = False,
        start: bool = True,
        cancel: CancelToken | None = None,
    ) -> str:
        """Create a stream (``POST /api/streams``); returns its id.

        Uses the default index set unless ``index_set_id`` is given and resumes the stream
        unless ``start=False`` (Graylog creates streams paused).
        """
        _check_title(title)
        if index_set_id is None:
            index_set_id = _default_index_set(self.list_index_sets(cancel=cancel))
        body = _stream_entity(
            title, description, index_set_id, rules, matching_type,
            remove_matches_from_default_stream,
        )  # fmt: skip
        req = Request("POST", "/api/streams", operation="create_stream", json=body)
        stream_id = _created_id(
            self._transport.request(req, cancel=cancel), "stream_id", "create_stream"
        )
        if start:
            self.resume_stream(stream_id, cancel=cancel)
        return stream_id

    def resume_stream(self, stream_id: str, *, cancel: CancelToken | None = None) -> None:
        """Start (resume) a paused stream: ``POST /api/streams/{id}/resume``."""
        path = f"/api/streams/{_seg(stream_id, 'resume_stream: stream_id')}/resume"
        req = Request("POST", path, operation="resume_stream", idempotent=True)
        self._transport.request(req, cancel=cancel)

    def delete_stream(self, stream_id: str, *, cancel: CancelToken | None = None) -> None:
        """Delete a stream: ``DELETE /api/streams/{id}``; :class:`NotFoundError` when unknown."""
        path = f"/api/streams/{_seg(stream_id, 'delete_stream: stream_id')}"
        self._transport.request(Request("DELETE", path, operation="delete_stream"), cancel=cancel)

    def list_index_sets(self, *, cancel: CancelToken | None = None) -> list[IndexSet]:
        """Every index set: ``GET /api/system/indices/index_sets?skip_stats=true``."""
        resp = self._get(
            "/api/system/indices/index_sets", "list_index_sets", cancel, params={"skip_stats": True}
        )
        sets = expect_object(resp, "list_index_sets").get("index_sets")
        return [decode_index_set(s) for s in sets] if isinstance(sets, list) else []

    # ---- search

    def search(
        self,
        query: str,
        *,
        range_s: int | None = None,
        from_: datetime | None = None,
        to: datetime | None = None,
        keyword: str | None = None,
        limit: int = 100,
        offset: int = 0,
        fields: Sequence[str] | None = None,
        sort: SearchSort | Sequence[SearchSort] | None = None,
        streams: Sequence[str] | None = None,
        cancel: CancelToken | None = None,
    ) -> SearchResult:
        """Search messages with a Lucene query (``POST /api/views/search/sync``).

        Give at most one of ``range_s`` (relative seconds; default 300), ``from_``/``to``
        (absolute; ``from_`` defaults to ``to`` - 300 s, ``to`` to now) and ``keyword`` (e.g.
        ``"last five minutes"``). ``fields`` limits the returned fields (plus ``_id``), ``sort``
        defaults to timestamp descending, ``streams`` limits the search to stream ids. An empty
        query matches everything. Query errors (HTTP 200 with ``errors``) raise
        :class:`ValidationError`.
        """
        req = _search_request(
            query, range_s=range_s, from_=from_, to=to, keyword=keyword, limit=limit,
            offset=offset, fields=fields, sort=sort, streams=streams,
        )  # fmt: skip
        return self._decode_search(self._transport.request(req, cancel=cancel), offset)

    def search_relative(
        self,
        query: str,
        seconds: int,
        *,
        limit: int = 100,
        offset: int = 0,
        fields: Sequence[str] | None = None,
        sort: SearchSort | Sequence[SearchSort] | None = None,
        streams: Sequence[str] | None = None,
        cancel: CancelToken | None = None,
    ) -> SearchResult:
        """:meth:`search` over the last ``seconds`` seconds (relative range)."""
        return self.search(
            query, range_s=seconds, limit=limit, offset=offset, fields=fields, sort=sort,
            streams=streams, cancel=cancel,
        )  # fmt: skip

    def get_message(
        self, index: str, message_id: str, *, cancel: CancelToken | None = None
    ) -> GraylogMessage:
        """One stored message: ``GET /api/messages/{index}/{id}``; :class:`NotFoundError`."""
        path = (
            f"/api/messages/{_seg(index, 'get_message: index')}"
            f"/{_seg(message_id, 'get_message: message_id')}"
        )
        return _decode_get_message(self._get(path, "get_message", cancel))

    def list_fields(self, *, cancel: CancelToken | None = None) -> list[str]:
        """Every indexed field name, sorted: ``GET /api/system/fields``."""
        return _list_fields(self._get("/api/system/fields", "list_fields", cancel))

    # ---- logging

    def log_client(
        self,
        protocol: LogProtocol | None = None,
        *,
        host: str | None = None,
        transport: GelfTransport | None = None,
        compression: GelfCompression | None = None,
        chunk_size: int | None = None,
        bulk: bool | None = None,
        headers: Mapping[str, str] | None = None,
        bearer_token: str | None = None,
        options: BatchOptions | None = None,
        resource: Mapping[str, AttrValue] | None = None,
        redaction: RedactionProcessor | None = _UNSET,
        correlate: bool = True,
    ) -> BatchingLogClient:
        """A batching log client sending through GELF (``udp``, ``tcp``, ``http``) or OTLP.

        Args:
            protocol: transport (default ``config.gelf_protocol``); ``otlp`` uses the
                OpenTelemetry (gRPC) input at ``config.otlp_grpc_endpoint()``.
            host: GELF ``host`` for records without ``resource["host.name"]``.
            transport: use this GELF transport instead of building one (closed with the client).
            compression: UDP payload compression (default ``gzip``).
            chunk_size: UDP chunk size (default 1420).
            bulk: HTTP bulk bodies (default True).
            headers: HTTP/OTLP extra headers (e.g. the input authorization header).
            bearer_token: OTLP bearer token configured on the input.
            options: batching options.
            resource: resource attributes of every record (``service.name`` …).
            redaction: redaction processor (default ``RedactionProcessor()``; ``None`` disables).
            correlate: add the active OpenTelemetry span ids to records.

        Log clients are flushed and closed by :meth:`close`.
        """
        if self._closed:
            raise ConfigError("log_client: client is closed")
        exporter = self._exporter(
            protocol, host, transport, compression, chunk_size, bulk, headers, bearer_token
        )
        client = BatchingLogClient(
            exporter, **self._client_kwargs(options, resource, redaction, correlate)
        )
        self._log_clients.append(client)
        return client

    def log_query_client(
        self,
        *,
        streams: Sequence[str] | None = None,
        default_window_s: float | timedelta = 3600.0,
    ) -> GraylogLogQueryClient:
        """A :class:`GraylogLogQueryClient` (search, polling tail, streams, fields)."""
        return GraylogLogQueryClient(self, streams=streams, default_window_s=default_window_s)

    def close(self) -> None:
        """Flush and close every log client from :meth:`log_client`, then release connections.

        Idempotent.
        """
        if self._closed:
            return
        self._closed = True
        clients, self._log_clients = self._log_clients, []
        for client in clients:
            with contextlib.suppress(Exception):
                client.close()
        self._resources.stop_all()
        self._transport.close()

    def __enter__(self) -> GraylogClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"GraylogClient(config={self.config!r})"


def _seconds(value: float | timedelta) -> float:
    return value.total_seconds() if isinstance(value, timedelta) else float(value)


# --------------------------------------------------------------------------- async


class AsyncGraylogClient(_ClientCore):
    """Asynchronous Graylog Open client; use ``async with`` or call :meth:`aclose`.

    Same methods as :class:`GraylogClient`, awaited. Cancel a call by cancelling its task: the
    SDK raises :class:`CancelledError`, which is also an :class:`asyncio.CancelledError`. GELF
    and OTLP exports run in worker threads.
    """

    def __init__(
        self,
        config: GraylogConfig | None = None,
        *,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        transport_config = self._setup(config)
        self._transport = AsyncHttpTransport(
            transport_config, known_secrets=self.config.known_secrets, http_transport=http_transport
        )
        self._log_clients: list[AsyncBatchingLogClient] = []
        self._closed = False

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **overrides: Any) -> AsyncGraylogClient:
        """Build a client from the ``GROW_GRAYLOG_*`` and vendor environment variables."""
        return cls(GraylogConfig.from_env(env, **overrides))

    async def request(self, req: Request) -> Response:
        """Send a raw request through the client's transport."""
        return await self._transport.request(req)

    async def _get(self, path: str, operation: str, **kw: Any) -> Response:
        return await self._transport.request(Request("GET", path, operation=operation, **kw))

    async def health(self) -> HealthStatus:
        """See :meth:`GraylogClient.health`."""
        try:
            resp = await self._transport.request(_HEALTH)
        except ServiceError as err:
            return _health_from_error(err)
        return _health_from_response(resp)

    async def ping(self) -> float:
        """See :meth:`GraylogClient.ping`."""
        started = time.monotonic()
        await self._get("/api/system", "ping")
        return (time.monotonic() - started) * 1000.0

    async def server_version(self) -> str:
        """See :meth:`GraylogClient.server_version`."""
        return _version(await self.system_info())

    async def system_info(self) -> SystemInfo:
        """See :meth:`GraylogClient.system_info`."""
        resp = await self._get("/api/system", "system_info")
        return decode_system_info(expect_object(resp, "system_info"))

    async def list_inputs(self) -> list[GraylogInput]:
        """See :meth:`GraylogClient.list_inputs`."""
        body = expect_object(await self._get("/api/system/inputs", "list_inputs"), "list_inputs")
        inputs = body.get("inputs")
        return [decode_input(i) for i in inputs] if isinstance(inputs, list) else []

    async def get_input(self, input_id: str) -> GraylogInput:
        """See :meth:`GraylogClient.get_input`."""
        path = f"/api/system/inputs/{_seg(input_id, 'get_input: input_id')}"
        return decode_input(expect_object(await self._get(path, "get_input"), "get_input"))

    async def get_input_state(self, input_id: str) -> InputState:
        """See :meth:`GraylogClient.get_input_state`."""
        path = f"/api/system/inputstates/{_seg(input_id, 'get_input_state: input_id')}"
        resp = await self._get(path, "get_input_state")
        return decode_input_state(expect_object(resp, "get_input_state"))

    async def list_input_types(self) -> dict[str, str]:
        """See :meth:`GraylogClient.list_input_types`."""
        resp = await self._get("/api/system/inputs/types", "list_input_types")
        types = expect_object(resp, "list_input_types").get("types")
        return {str(k): str(v) for k, v in types.items()} if isinstance(types, dict) else {}

    async def create_input(
        self,
        input_type: str,
        configuration: Mapping[str, Any],
        *,
        title: str | None = None,
        global_: bool = True,
        node: str | None = None,
    ) -> str:
        """See :meth:`GraylogClient.create_input`."""
        req = _create_input_request(input_type, configuration, title, global_, node)
        return _created_id(await self._transport.request(req), "id", "create_input")

    async def ensure_gelf_input(
        self,
        protocol: GelfProtocol,
        port: int,
        *,
        title: str | None = None,
        bind_address: str = "0.0.0.0",  # noqa: S104 - Graylog input bind address
        configuration: Mapping[str, Any] | None = None,
        timeout_s: float | timedelta = 30.0,
        interval_s: float | timedelta = 0.5,
    ) -> EnsuredInput:
        """See :meth:`GraylogClient.ensure_gelf_input`."""
        input_type = _ensure_type(protocol, port)
        inp = _ensure_match(await self.list_inputs(), input_type, port, bind_address)
        created = False
        if inp is None:
            config = {
                **_gelf_input_configuration(protocol, port, bind_address),
                **(configuration or {}),
            }
            new_id = await self.create_input(
                input_type, config, title=title or f"grow-codes GELF {protocol.upper()} {port}"
            )
            created = True
            inp = next(
                (i for i in await self.list_inputs() if i.id == new_id), None
            ) or await self.get_input(new_id)
        path = f"/api/system/inputstates/{quote(inp.id, safe='')}"

        async def attempt() -> InputState | None:
            resp = await self._get(path, "ensure_gelf_input", raise_for_status=False)
            return _input_state_or_none(resp)

        try:
            state = await apoll_until(
                attempt,
                predicate=_state_done,
                timeout_s=_seconds(timeout_s),
                interval_s=_seconds(interval_s),
                operation=f"ensure_gelf_input {protocol}:{port}",
            )
        except TimeoutError:
            if created:
                await self._delete_quietly(inp.id)
            raise
        if state.state == "FAILED":
            if created:
                await self._delete_quietly(inp.id)
            raise self._failed_input(protocol, port, state)
        return ensured_input(inp, created)

    async def _delete_quietly(self, input_id: str) -> None:
        try:
            await self.delete_input(input_id)
        except asyncio.CancelledError:
            raise
        except ServiceError:
            pass

    async def delete_input(self, input_id: str) -> None:
        """See :meth:`GraylogClient.delete_input`."""
        path = f"/api/system/inputs/{_seg(input_id, 'delete_input: input_id')}"
        await self._transport.request(Request("DELETE", path, operation="delete_input"))

    async def list_streams(
        self,
        *,
        page: int = 1,
        per_page: int = 50,
        query: str | None = None,
        sort: str = "title",
        order: Literal["asc", "desc"] = "asc",
    ) -> StreamPage:
        """See :meth:`GraylogClient.list_streams`."""
        req = _list_streams_request(page, per_page, query, sort, order)
        body = expect_object(await self._transport.request(req), "list_streams")
        return decode_stream_page(body, page, per_page)

    async def get_stream(self, stream_id: str) -> GraylogStream:
        """See :meth:`GraylogClient.get_stream`."""
        path = f"/api/streams/{_seg(stream_id, 'get_stream: stream_id')}"
        return decode_stream(expect_object(await self._get(path, "get_stream"), "get_stream"))

    async def create_stream(
        self,
        title: str,
        *,
        description: str = "",
        index_set_id: str | None = None,
        rules: Sequence[StreamRule] = (),
        matching_type: Literal["AND", "OR"] = "AND",
        remove_matches_from_default_stream: bool = False,
        start: bool = True,
    ) -> str:
        """See :meth:`GraylogClient.create_stream`."""
        _check_title(title)
        if index_set_id is None:
            index_set_id = _default_index_set(await self.list_index_sets())
        body = _stream_entity(
            title, description, index_set_id, rules, matching_type,
            remove_matches_from_default_stream,
        )  # fmt: skip
        req = Request("POST", "/api/streams", operation="create_stream", json=body)
        stream_id = _created_id(await self._transport.request(req), "stream_id", "create_stream")
        if start:
            await self.resume_stream(stream_id)
        return stream_id

    async def resume_stream(self, stream_id: str) -> None:
        """See :meth:`GraylogClient.resume_stream`."""
        path = f"/api/streams/{_seg(stream_id, 'resume_stream: stream_id')}/resume"
        await self._transport.request(
            Request("POST", path, operation="resume_stream", idempotent=True)
        )

    async def delete_stream(self, stream_id: str) -> None:
        """See :meth:`GraylogClient.delete_stream`."""
        path = f"/api/streams/{_seg(stream_id, 'delete_stream: stream_id')}"
        await self._transport.request(Request("DELETE", path, operation="delete_stream"))

    async def list_index_sets(self) -> list[IndexSet]:
        """See :meth:`GraylogClient.list_index_sets`."""
        resp = await self._get(
            "/api/system/indices/index_sets", "list_index_sets", params={"skip_stats": True}
        )
        sets = expect_object(resp, "list_index_sets").get("index_sets")
        return [decode_index_set(s) for s in sets] if isinstance(sets, list) else []

    async def search(
        self,
        query: str,
        *,
        range_s: int | None = None,
        from_: datetime | None = None,
        to: datetime | None = None,
        keyword: str | None = None,
        limit: int = 100,
        offset: int = 0,
        fields: Sequence[str] | None = None,
        sort: SearchSort | Sequence[SearchSort] | None = None,
        streams: Sequence[str] | None = None,
    ) -> SearchResult:
        """See :meth:`GraylogClient.search`."""
        req = _search_request(
            query, range_s=range_s, from_=from_, to=to, keyword=keyword, limit=limit,
            offset=offset, fields=fields, sort=sort, streams=streams,
        )  # fmt: skip
        return self._decode_search(await self._transport.request(req), offset)

    async def search_relative(
        self,
        query: str,
        seconds: int,
        *,
        limit: int = 100,
        offset: int = 0,
        fields: Sequence[str] | None = None,
        sort: SearchSort | Sequence[SearchSort] | None = None,
        streams: Sequence[str] | None = None,
    ) -> SearchResult:
        """See :meth:`GraylogClient.search_relative`."""
        return await self.search(
            query, range_s=seconds, limit=limit, offset=offset, fields=fields, sort=sort,
            streams=streams,
        )  # fmt: skip

    async def get_message(self, index: str, message_id: str) -> GraylogMessage:
        """See :meth:`GraylogClient.get_message`."""
        path = (
            f"/api/messages/{_seg(index, 'get_message: index')}"
            f"/{_seg(message_id, 'get_message: message_id')}"
        )
        return _decode_get_message(await self._get(path, "get_message"))

    async def list_fields(self) -> list[str]:
        """See :meth:`GraylogClient.list_fields`."""
        return _list_fields(await self._get("/api/system/fields", "list_fields"))

    def log_client(
        self,
        protocol: LogProtocol | None = None,
        *,
        host: str | None = None,
        transport: GelfTransport | None = None,
        compression: GelfCompression | None = None,
        chunk_size: int | None = None,
        bulk: bool | None = None,
        headers: Mapping[str, str] | None = None,
        bearer_token: str | None = None,
        options: BatchOptions | None = None,
        resource: Mapping[str, AttrValue] | None = None,
        redaction: RedactionProcessor | None = _UNSET,
        correlate: bool = True,
    ) -> AsyncBatchingLogClient:
        """Async batching log client; see :meth:`GraylogClient.log_client`."""
        if self._closed:
            raise ConfigError("log_client: client is closed")
        exporter = self._exporter(
            protocol, host, transport, compression, chunk_size, bulk, headers, bearer_token
        )
        client = AsyncBatchingLogClient(
            ThreadedAsyncLogExporter(exporter),
            **self._client_kwargs(options, resource, redaction, correlate),
        )
        self._log_clients.append(client)
        return client

    def log_query_client(
        self,
        *,
        streams: Sequence[str] | None = None,
        default_window_s: float | timedelta = 3600.0,
    ) -> AsyncGraylogLogQueryClient:
        """An :class:`AsyncGraylogLogQueryClient`."""
        return AsyncGraylogLogQueryClient(self, streams=streams, default_window_s=default_window_s)

    async def aclose(self) -> None:
        """Flush and close every log client, then release connections (idempotent)."""
        if self._closed:
            return
        self._closed = True
        clients, self._log_clients = self._log_clients, []
        for client in clients:
            with contextlib.suppress(Exception):
                await client.close()
        self._resources.stop_all()
        await self._transport.aclose()

    close = aclose

    async def __aenter__(self) -> AsyncGraylogClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        return f"AsyncGraylogClient(config={self.config!r})"
