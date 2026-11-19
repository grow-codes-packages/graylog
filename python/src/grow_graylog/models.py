"""Typed models of the Graylog REST API (snake_case) and their decoders."""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal

from ._core import UnavailableError, ValidationError
from ._core.http import Response
from ._logging import parse_timestamp

__all__ = [
    "GELF_INPUT_TYPES",
    "OTLP_GRPC_INPUT_TYPE",
    "EnsuredInput",
    "GraylogInput",
    "GraylogMessage",
    "GraylogStream",
    "IndexSet",
    "InputState",
    "SearchResult",
    "SearchSort",
    "StreamPage",
    "StreamRule",
    "SystemInfo",
]

#: Input class names of the GELF inputs, by protocol.
GELF_INPUT_TYPES: Mapping[str, str] = {
    "udp": "org.graylog2.inputs.gelf.udp.GELFUDPInput",
    "tcp": "org.graylog2.inputs.gelf.tcp.GELFTCPInput",
    "http": "org.graylog2.inputs.gelf.http.GELFHttpInput",
}

#: Input class name of the OpenTelemetry (gRPC) input.
OTLP_GRPC_INPUT_TYPE = "org.graylog.inputs.otel.OTelGrpcInput"


@dataclasses.dataclass(frozen=True)
class SystemInfo:
    """``GET /api/system`` (:meth:`GraylogClient.system_info`)."""

    facility: str
    codename: str
    node_id: str
    cluster_id: str
    #: As reported, e.g. ``7.0.16+58e0f6e``.
    version: str
    started_at: datetime | None
    hostname: str
    lifecycle: str
    lb_status: str
    timezone: str
    operating_system: str
    is_leader: bool
    is_processing: bool


@dataclasses.dataclass(frozen=True)
class GraylogInput:
    """A configured input (``GET /api/system/inputs``)."""

    id: str
    title: str
    #: Input class, e.g. ``GELF_INPUT_TYPES["tcp"]``.
    type: str
    #: Human name of the type, e.g. ``GELF TCP``.
    name: str
    global_: bool
    #: Node id for node-local inputs, ``None`` for global ones.
    node: str | None
    created_at: datetime | None
    creator_user_id: str | None
    #: Configuration as returned (secret values come back as ``{"is_set": ...}`` objects).
    attributes: Mapping[str, Any]
    static_fields: Mapping[str, str]
    #: ``attributes["port"]`` when numeric.
    port: int | None
    #: ``attributes["bind_address"]`` when present.
    bind_address: str | None


@dataclasses.dataclass(frozen=True)
class EnsuredInput(GraylogInput):
    """Result of :meth:`GraylogClient.ensure_gelf_input`."""

    #: Whether this call created the input.
    created: bool = False


@dataclasses.dataclass(frozen=True)
class InputState:
    """Runtime state of an input (``GET /api/system/inputstates/{id}``)."""

    id: str
    #: ``RUNNING``, ``STARTING``, ``FAILED``, ``STOPPED`` …
    state: str
    started_at: datetime | None
    detailed_message: str | None
    input: GraylogInput | None


@dataclasses.dataclass(frozen=True)
class StreamRule:
    """A stream rule.

    ``type``: 1 exact, 2 regex, 3 greater, 4 smaller, 5 presence, 6 contain, 7 always, 8 input.
    """

    field: str
    type: int
    value: str
    inverted: bool = False
    description: str = ""
    id: str | None = None


@dataclasses.dataclass(frozen=True)
class GraylogStream:
    """A stream."""

    id: str
    title: str
    description: str
    disabled: bool
    index_set_id: str
    is_default: bool
    #: ``AND`` or ``OR``.
    matching_type: str
    remove_matches_from_default_stream: bool
    rules: list[StreamRule]
    created_at: datetime | None
    creator_user_id: str | None


@dataclasses.dataclass(frozen=True)
class StreamPage:
    """One page of ``GET /api/streams/paginated``."""

    streams: list[GraylogStream]
    #: Streams matching the query.
    total: int
    #: 1-based page number.
    page: int
    per_page: int


@dataclasses.dataclass(frozen=True)
class IndexSet:
    """An index set (``GET /api/system/indices/index_sets``)."""

    id: str
    title: str
    description: str
    index_prefix: str
    #: Whether this is the default index set.
    is_default: bool
    writable: bool
    shards: int
    replicas: int
    created_at: datetime | None


@dataclasses.dataclass(frozen=True)
class GraylogMessage:
    """A stored message (search hit or :meth:`GraylogClient.get_message`)."""

    #: Message id (``_id``).
    id: str
    #: OpenSearch index holding it (pass to ``get_message``).
    index: str
    timestamp: datetime | None
    #: Every stored field (including ``message``, ``source``, ``timestamp``, ``gl2_*``).
    fields: Mapping[str, Any]


@dataclasses.dataclass(frozen=True)
class SearchSort:
    """Sort order of search results."""

    field: str
    #: ``asc`` or ``desc`` (default).
    order: Literal["asc", "desc"] = "desc"


@dataclasses.dataclass(frozen=True)
class SearchResult:
    """Result of :meth:`GraylogClient.search` / :meth:`GraylogClient.search_relative`."""

    messages: list[GraylogMessage]
    #: Total matches in the time range (may exceed ``len(messages)``).
    total: int
    #: Resolved time range.
    from_: datetime | None
    to: datetime | None
    #: Offset of the next page, when more results exist.
    next_offset: int | None = None


# --------------------------------------------------------------------------- decoders


def _obj(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _str(v: Any, fallback: str = "") -> str:
    return v if isinstance(v, str) else fallback


def _str_or_none(v: Any) -> str | None:
    return v if isinstance(v, str) else None


def _int(v: Any, fallback: int = 0) -> int:
    if isinstance(v, bool):
        return fallback
    if isinstance(v, int):
        return v
    if isinstance(v, float) and v.is_integer():
        return int(v)
    return fallback


def _bool(v: Any) -> bool:
    return v is True


def date_or_none(v: Any) -> datetime | None:
    """Parse an ISO-8601 date; ``None`` when absent or invalid."""
    if not isinstance(v, str):
        return None
    try:
        return parse_timestamp(v)
    except ValidationError:
        return None


def expect_object(resp: Response, operation: str) -> dict[str, Any]:
    """The JSON object of a response; :class:`UnavailableError` when it is not an object."""
    try:
        data = resp.json()
    except ValidationError:
        data = None
    if not isinstance(data, dict):
        raise UnavailableError(
            f"{operation}: unexpected response", http_status=resp.status, retryable=False
        )
    return data


def decode_system_info(v: Any) -> SystemInfo:
    o = _obj(v)
    return SystemInfo(
        facility=_str(o.get("facility")),
        codename=_str(o.get("codename")),
        node_id=_str(o.get("node_id")),
        cluster_id=_str(o.get("cluster_id")),
        version=_str(o.get("version")),
        started_at=date_or_none(o.get("started_at")),
        hostname=_str(o.get("hostname")),
        lifecycle=_str(o.get("lifecycle")),
        lb_status=_str(o.get("lb_status")),
        timezone=_str(o.get("timezone")),
        operating_system=_str(o.get("operating_system")),
        is_leader=_bool(o.get("is_leader")),
        is_processing=_bool(o.get("is_processing")),
    )


def _input_kwargs(v: Any) -> dict[str, Any]:
    o = _obj(v)
    attributes = _obj(o.get("attributes"))
    port = attributes.get("port")
    return {
        "id": _str(o.get("id")),
        "title": _str(o.get("title")),
        "type": _str(o.get("type")),
        "name": _str(o.get("name")),
        "global_": _bool(o.get("global")),
        "node": _str_or_none(o.get("node")),
        "created_at": date_or_none(o.get("created_at")),
        "creator_user_id": _str_or_none(o.get("creator_user_id")),
        "attributes": attributes,
        "static_fields": {str(k): str(x) for k, x in _obj(o.get("static_fields")).items()},
        "port": port if isinstance(port, int) and not isinstance(port, bool) else None,
        "bind_address": _str_or_none(attributes.get("bind_address")),
    }


def decode_input(v: Any) -> GraylogInput:
    return GraylogInput(**_input_kwargs(v))


def ensured_input(inp: GraylogInput, created: bool) -> EnsuredInput:
    fields = {f.name: getattr(inp, f.name) for f in dataclasses.fields(GraylogInput)}
    return EnsuredInput(**fields, created=created)


def decode_input_state(v: Any) -> InputState:
    o = _obj(v)
    message_input = o.get("message_input")
    return InputState(
        id=_str(o.get("id")),
        state=_str(o.get("state"), "UNKNOWN"),
        started_at=date_or_none(o.get("started_at")),
        detailed_message=_str_or_none(o.get("detailed_message")),
        input=decode_input(message_input) if isinstance(message_input, dict) else None,
    )


def decode_stream_rule(v: Any) -> StreamRule:
    o = _obj(v)
    value = o.get("value")
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (str, int, float)):
        text = str(value)
    else:
        text = ""
    return StreamRule(
        field=_str(o.get("field")),
        type=_int(o.get("type")),
        value=text,
        inverted=_bool(o.get("inverted")),
        description=_str(o.get("description")),
        id=_str_or_none(o.get("id")),
    )


def decode_stream(v: Any) -> GraylogStream:
    o = _obj(v)
    rules = o.get("rules")
    return GraylogStream(
        id=_str(o.get("id")),
        title=_str(o.get("title")),
        description=_str(o.get("description")),
        disabled=_bool(o.get("disabled")),
        index_set_id=_str(o.get("index_set_id")),
        is_default=_bool(o.get("is_default")),
        matching_type=_str(o.get("matching_type"), "AND"),
        remove_matches_from_default_stream=_bool(o.get("remove_matches_from_default_stream")),
        rules=[decode_stream_rule(r) for r in rules] if isinstance(rules, list) else [],
        created_at=date_or_none(o.get("created_at")),
        creator_user_id=_str_or_none(o.get("creator_user_id")),
    )


def decode_index_set(v: Any) -> IndexSet:
    o = _obj(v)
    return IndexSet(
        id=_str(o.get("id")),
        title=_str(o.get("title")),
        description=_str(o.get("description")),
        index_prefix=_str(o.get("index_prefix")),
        is_default=_bool(o.get("default")),
        writable=_bool(o.get("writable")),
        shards=_int(o.get("shards")),
        replicas=_int(o.get("replicas")),
        created_at=date_or_none(o.get("creation_date")),
    )


def decode_message(fields: Any, index: Any) -> GraylogMessage:
    f = _obj(fields)
    return GraylogMessage(
        id=_str(f.get("_id"), _str(f.get("id"))),
        index=_str(index),
        timestamp=date_or_none(f.get("timestamp")),
        fields=f,
    )


def decode_stream_page(body: dict[str, Any], page: int, per_page: int) -> StreamPage:
    pagination = _obj(body.get("pagination"))
    elements = body.get("elements")
    streams = [decode_stream(s) for s in elements] if isinstance(elements, list) else []
    return StreamPage(
        streams=streams,
        total=_int(pagination.get("total"), _int(body.get("total"), len(streams))),
        page=_int(pagination.get("page"), page),
        per_page=_int(pagination.get("per_page"), per_page),
    )


def decode_search(body: dict[str, Any], offset: int, redact: Any) -> SearchResult:
    """Decode a views search response; query errors raise :class:`ValidationError`."""
    q1 = _obj(_obj(body.get("results")).get("q1"))
    errors: list[Any] = []
    for source in (body.get("errors"), q1.get("errors")):
        if isinstance(source, list):
            errors.extend(source)
    execution = _obj(body.get("execution"))
    if errors or execution.get("completed_exceptionally") is True:
        description = next(
            (
                e["description"]
                for e in errors
                if isinstance(e, dict) and isinstance(e.get("description"), str)
            ),
            "query failed",
        )
        raise ValidationError(f"search: {redact(description)[:300]}")
    st = _obj(_obj(q1.get("search_types")).get("st1"))
    raw = st.get("messages")
    hits = raw if isinstance(raw, list) else []
    messages = [decode_message(_obj(m).get("message"), _obj(m).get("index")) for m in hits]
    total = _int(st.get("total_results"), len(messages))
    stats = _obj(q1.get("execution_stats"))
    rng = _obj(st.get("effective_timerange") or stats.get("effective_timerange"))
    next_offset = offset + len(messages) if messages and offset + len(messages) < total else None
    return SearchResult(
        messages=messages,
        total=total,
        from_=date_or_none(rng.get("from")),
        to=date_or_none(rng.get("to")),
        next_offset=next_offset,
    )
