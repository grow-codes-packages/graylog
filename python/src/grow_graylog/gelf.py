"""GELF 1.1 messages, severity ↔ syslog level mapping and the attribute mapping.

The attribute mapping (coordinator decision 3) is identical in all five languages: keys get a
``_`` prefix, characters outside ``[A-Za-z0-9_.-]`` become ``_``, ``id`` becomes ``_attr_id``;
booleans become ``"true"``/``"false"``, ``None`` is omitted, numbers stay numbers, lists and
mappings become compact JSON strings; resource attributes are flattened with dotted keys.
"""

from __future__ import annotations

import enum
import json
import math
import re
import socket
from collections.abc import Iterator, Mapping
from datetime import datetime, timezone
from typing import Any

from ._core import ValidationError
from ._logging import AttrValue, LogRecord, Severity
from .models import date_or_none

__all__ = [
    "GELF_VERSION",
    "GelfFieldValue",
    "GelfLevel",
    "GelfMessage",
    "RESOURCE_FIELDS",
    "flatten_attributes",
    "gelf_field_key",
    "gelf_field_value",
    "gelf_level_to_severity",
    "log_record_from_message",
    "severity_to_gelf_level",
    "to_gelf_timestamp",
    "validate_gelf_field_key",
]

#: GELF specification version written into every message.
GELF_VERSION = "1.1"

GelfFieldValue = str | int | float
"""A GELF additional field value as written on the wire."""


class GelfLevel(enum.IntEnum):
    """Syslog severity levels used by the GELF ``level`` field."""

    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFORMATIONAL = 6
    DEBUG = 7


def _canonical(severity: int) -> int:
    n = min(24, max(1, int(severity)))
    return n - ((n - 1) % 4)


def severity_to_gelf_level(severity: Severity | int) -> GelfLevel:
    """OTel severity → syslog level: TRACE/DEBUG → 7, INFO → 6, WARN → 4, ERROR → 3, FATAL → 2.

    Numbers between the named values use the band they fall into.
    """
    band = _canonical(int(severity))
    if band in (Severity.TRACE, Severity.DEBUG):
        return GelfLevel.DEBUG
    if band == Severity.WARN:
        return GelfLevel.WARNING
    if band == Severity.ERROR:
        return GelfLevel.ERROR
    if band == Severity.FATAL:
        return GelfLevel.CRITICAL
    return GelfLevel.INFORMATIONAL


def gelf_level_to_severity(level: float) -> Severity:
    """Syslog level → OTel severity: 0-2 → FATAL, 3 → ERROR, 4 → WARN, 5-6 → INFO, 7 → DEBUG."""
    if not math.isfinite(level):
        return Severity.INFO
    n = math.trunc(level)
    if n <= 2:
        return Severity.FATAL
    if n == 3:
        return Severity.ERROR
    if n == 4:
        return Severity.WARN
    if n >= 7:
        return Severity.DEBUG
    return Severity.INFO


_KEY_CHARS = re.compile(r"^[\w.-]+$", re.ASCII)
_KEY_SANITIZE = re.compile(r"[^\w.-]", re.ASCII)


def gelf_field_key(name: str) -> str:
    """Map an attribute name to its GELF additional field key (decision 3).

    ``_`` prefix, every character outside ``[A-Za-z0-9_.-]`` becomes ``_``, and ``id`` (reserved
    by GELF) becomes ``_attr_id``.
    """
    if name == "id":
        return "_attr_id"
    return "_" + _KEY_SANITIZE.sub("_", name)


def _json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str)


def gelf_field_value(value: Any) -> GelfFieldValue | None:
    """Map an attribute value to its GELF form (decision 3).

    Strings and finite numbers unchanged, booleans → ``"true"``/``"false"``, ``None`` → omitted
    (``None``), non-finite numbers → their text, datetimes → ISO-8601, lists and mappings →
    compact JSON strings.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return "NaN" if math.isnan(value) else ("Infinity" if value > 0 else "-Infinity")
    if value is None:
        return None
    if isinstance(value, datetime):
        return _iso(value)
    if isinstance(value, (Mapping, list, tuple)):
        return _json(value)
    return str(value)


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    utc = value.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def validate_gelf_field_key(key: str) -> str:
    """Validate an explicit additional field key for :meth:`GelfMessage.set_field`.

    Accepts ``name`` or ``_name`` and returns the ``_name`` wire key. Raises
    :class:`ValidationError` for keys outside ``[A-Za-z0-9_.-]``, empty keys and the reserved
    ``id``.
    """
    name = key[1:] if key.startswith("_") else key
    if not name or not _KEY_CHARS.match(name):
        raise ValidationError(
            f"gelf: invalid additional field key {key!r} (allowed: letters, digits, _ . -)"
        )
    if name == "id":
        raise ValidationError('gelf: additional field "_id" is reserved')
    return "_" + name


def to_gelf_timestamp(value: datetime) -> float:
    """Unix seconds with millisecond precision (naive datetimes are taken as UTC)."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return round(value.timestamp() * 1000) / 1000


def flatten_attributes(
    attributes: Mapping[str, AttrValue], prefix: str = ""
) -> Iterator[tuple[str, AttrValue]]:
    """Flatten nested mappings into dotted keys; lists and scalars are leaves."""
    for k, v in attributes.items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, Mapping):
            yield from flatten_attributes(v, key)
        else:
            yield key, v


class GelfMessage:
    """One GELF 1.1 message.

    Build it with the constructor and :meth:`set_field`, or from a :class:`LogRecord` with
    :meth:`from_log_record`; serialise with :meth:`to_json` (dict), :meth:`to_json_str` or
    :meth:`encode` (UTF-8 bytes).

    Args:
        host: source host (stored as ``source``); required, not blank.
        short_message: short message (stored as ``message``); required, not blank.
        full_message: long message (e.g. a stack trace).
        timestamp: event time, a ``datetime`` or Unix seconds.
        level: syslog level 0-7.
        fields: additional fields; keys are validated like :meth:`set_field`.

    Raises:
        ValidationError: for a blank host or message, a bad level, timestamp or field key.
    """

    version = GELF_VERSION

    def __init__(
        self,
        host: str,
        short_message: str,
        *,
        full_message: str | None = None,
        timestamp: datetime | float | None = None,
        level: GelfLevel | int | None = None,
        fields: Mapping[str, Any] | None = None,
    ) -> None:
        if not isinstance(host, str) or not host.strip():
            raise ValidationError("gelf: host must not be blank")
        if not isinstance(short_message, str) or not short_message.strip():
            raise ValidationError("gelf: short_message must not be blank")
        self.host = host
        self.short_message = short_message
        self.full_message = full_message
        self.timestamp: float | None = None
        if timestamp is not None:
            if isinstance(timestamp, datetime):
                ts = to_gelf_timestamp(timestamp)
            elif isinstance(timestamp, (int, float)) and not isinstance(timestamp, bool):
                ts = float(timestamp)
            else:
                raise ValidationError("gelf: invalid timestamp")
            if not math.isfinite(ts):
                raise ValidationError("gelf: invalid timestamp")
            self.timestamp = ts
        self.level: int | None = None
        if level is not None:
            if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 7:
                raise ValidationError("gelf: level must be an integer 0..7")
            self.level = int(level)
        self._fields: dict[str, GelfFieldValue] = {}
        for k, v in (fields or {}).items():
            self.set_field(k, v)

    def set_field(self, key: str, value: Any) -> GelfMessage:
        """Set an additional field (``name`` or ``_name``); returns ``self`` for chaining.

        The key is validated (:func:`validate_gelf_field_key`); the value is mapped by
        :func:`gelf_field_value` and a ``None`` value removes the field.
        """
        wire = validate_gelf_field_key(key)
        mapped = gelf_field_value(value)
        if mapped is None:
            self._fields.pop(wire, None)
        else:
            self._fields[wire] = mapped
        return self

    @property
    def fields(self) -> dict[str, GelfFieldValue]:
        """Additional fields with their ``_`` keys (a copy)."""
        return dict(self._fields)

    @classmethod
    def from_log_record(cls, record: LogRecord, *, host: str | None = None) -> GelfMessage:
        """Convert a log record (decision 3).

        ``host`` = ``resource["host.name"]`` (else the ``host`` argument, else the machine host
        name), ``short_message`` = body (``"-"`` when blank), ``timestamp``, ``level`` from the
        severity, resource attributes flattened with dotted keys (except ``host.name``), then
        the record attributes, then ``_trace_id``, ``_span_id``, ``_trace_flags``. Keys are
        sanitised with :func:`gelf_field_key`, values mapped with :func:`gelf_field_value`.
        """
        resource_host = record.resource.get("host.name")
        if isinstance(resource_host, str) and resource_host.strip():
            source = resource_host
        else:
            source = host if host is not None else socket.gethostname()
        msg = cls(
            host=source if source.strip() else "unknown",
            short_message=record.body if record.body.strip() else "-",
            timestamp=record.timestamp,
            level=severity_to_gelf_level(record.severity),
        )

        def put(name: str, value: Any) -> None:
            if not name:
                return
            mapped = gelf_field_value(value)
            if mapped is not None:
                msg._fields[gelf_field_key(name)] = mapped

        for k, v in flatten_attributes(record.resource):
            if k != "host.name":
                put(k, v)
        for k, v in record.attributes.items():
            put(str(k), v)
        if record.trace_id is not None:
            put("trace_id", record.trace_id)
        if record.span_id is not None:
            put("span_id", record.span_id)
        if record.trace_flags is not None:
            put("trace_flags", record.trace_flags)
        return msg

    def to_json(self) -> dict[str, Any]:
        """The GELF wire object."""
        out: dict[str, Any] = {
            "version": self.version,
            "host": self.host,
            "short_message": self.short_message,
        }
        if self.full_message is not None:
            out["full_message"] = self.full_message
        if self.timestamp is not None:
            out["timestamp"] = self.timestamp
        if self.level is not None:
            out["level"] = self.level
        out.update(self._fields)
        return out

    def to_json_str(self) -> str:
        """Compact JSON text."""
        return _json(self.to_json())

    def encode(self) -> bytes:
        """UTF-8 JSON bytes."""
        return self.to_json_str().encode("utf-8")

    def __repr__(self) -> str:
        return f"GelfMessage({self.to_json_str()})"


# --------------------------------------------------------------------------- read back

#: Stored field names (Graylog replaces ``.`` by ``_``) that map back to OTel resource keys.
RESOURCE_FIELDS: Mapping[str, str] = {
    "service_name": "service.name",
    "service_version": "service.version",
    "service_namespace": "service.namespace",
    "service_instance_id": "service.instance.id",
    "deployment_environment": "deployment.environment",
    "deployment_environment_name": "deployment.environment.name",
}

_SKIPPED_FIELDS = frozenset(
    {
        "_id",
        "message",
        "timestamp",
        "level",
        "source",
        "streams",
        "trace_id",
        "span_id",
        "trace_flags",
        "otel_trace_id",
        "otel_span_id",
        "otel_trace_flags",
        "otel_severity_number",
        "otel_severity_text",
        "otel_time_unix_nano",
        "otel_observed_time_unix_nano",
        "otel_resource_schema_url",
        "otel_scope_schema_url",
    }
)
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX16 = re.compile(r"^[0-9a-f]{16}$")
_NUMBER = re.compile(r"^-?\d+(\.\d+)?$")
_RES_PREFIX = "otel_resource_attributes_"
_ATTR_PREFIX = "otel_attributes_"


def _as_number(v: Any) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v) if math.isfinite(v) else None
    if isinstance(v, str) and _NUMBER.match(v.strip()):
        return float(v)
    return None


def _hex_id(v: Any, pattern: re.Pattern[str]) -> str | None:
    if not isinstance(v, str):
        return None
    s = v.strip().lower()
    return s if pattern.match(s) else None


def _attr_value(v: Any) -> AttrValue | None:
    if isinstance(v, (str, bool, int)):
        return v
    if isinstance(v, float):
        return v if math.isfinite(v) else str(v)
    if isinstance(v, list):
        return [x for x in (_attr_value(i) for i in v) if x is not None]
    if isinstance(v, dict):
        out: dict[str, AttrValue] = {}
        for k, inner in v.items():
            a = _attr_value(inner)
            if a is not None:
                out[str(k)] = a
        return out
    return None


def _body_text(v: Any) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return "" if v is None else _json(v)


def log_record_from_message(fields: Mapping[str, Any]) -> LogRecord:
    """Normalise a stored Graylog message (search hit or ``get_message`` fields) into a record.

    OTLP fields (``otel_*``) win over GELF fields. ``source`` → ``resource["host.name"]``, known
    resource fields (:data:`RESOURCE_FIELDS`) and ``otel_resource_attributes_*`` → resource,
    ``attr_id`` → ``id``, ``otel_attributes_*`` and every other field except ``gl2_*`` and the
    reserved ones → attributes.
    """
    ts = fields.get("timestamp")
    timestamp: datetime | None = None
    if isinstance(ts, str):
        timestamp = date_or_none(ts)
    otel_severity = _as_number(fields.get("otel_severity_number"))
    level = _as_number(fields.get("level"))
    if otel_severity is not None and 1 <= otel_severity <= 24:
        severity = Severity(_canonical(int(otel_severity)))
    elif level is not None:
        severity = gelf_level_to_severity(level)
    else:
        severity = Severity.INFO
    attributes: dict[str, AttrValue] = {}
    resource: dict[str, AttrValue] = {}
    source = fields.get("source")
    if isinstance(source, str) and source:
        resource["host.name"] = source
    for key, value in fields.items():
        if key in _SKIPPED_FIELDS or key.startswith("gl2_"):
            continue
        v = _attr_value(value)
        if v is None:
            continue
        if key.startswith(_RES_PREFIX):
            name = key[len(_RES_PREFIX) :]
            resource[RESOURCE_FIELDS.get(name, name)] = v
        elif key.startswith(_ATTR_PREFIX):
            attributes[key[len(_ATTR_PREFIX) :]] = v
        elif key in RESOURCE_FIELDS:
            resource.setdefault(RESOURCE_FIELDS[key], v)
        elif key == "attr_id":
            attributes["id"] = v
        else:
            attributes[key] = v
    trace_id = _hex_id(fields.get("otel_trace_id"), _HEX32) or _hex_id(
        fields.get("trace_id"), _HEX32
    )
    span_id: str | None = None
    flags: int | None = None
    if trace_id is not None:
        span_id = _hex_id(fields.get("otel_span_id"), _HEX16) or _hex_id(
            fields.get("span_id"), _HEX16
        )
        raw_flags = _as_number(fields.get("otel_trace_flags"))
        if raw_flags is None:
            raw_flags = _as_number(fields.get("trace_flags"))
        flags = int(raw_flags) if raw_flags is not None else None
    return LogRecord(
        body=_body_text(fields.get("message")),
        severity=severity,
        timestamp=timestamp or datetime.fromtimestamp(0, timezone.utc),
        attributes=attributes,
        resource=resource,
        trace_id=trace_id,
        span_id=span_id,
        trace_flags=flags,
    )
