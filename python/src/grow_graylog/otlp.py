"""Optional OTLP/gRPC logs exporter for the Graylog OpenTelemetry (gRPC) input.

Graylog Open 7.0 has no OTLP/HTTP input, so this speaks gRPC. It needs the ``otlp`` extra
(``pip install "grow-graylog[otlp]"``, which installs ``grpcio``); the protobuf messages come
from ``opentelemetry-proto``.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from opentelemetry.proto.collector.logs.v1 import logs_service_pb2
from opentelemetry.proto.common.v1 import common_pb2
from opentelemetry.proto.logs.v1 import logs_pb2
from opentelemetry.proto.resource.v1 import resource_pb2

from ._core import (
    AuthenticationError,
    CancelledError,
    ConfigError,
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    Secret,
    ServiceError,
    TimeoutError,
    TlsConfig,
    UnavailableError,
    UnsupportedError,
    ValidationError,
    redact_text,
    user_agent,
)
from ._logging import AttrValue, ExportResult, LogRecord
from ._version import __version__

__all__ = [
    "OTLP_LOGS_EXPORT_PATH",
    "OtlpGrpcLogExporter",
    "OtlpPartialSuccess",
    "decode_export_logs_response",
    "encode_export_logs_request",
    "error_for_grpc_status",
]

#: gRPC method path of the OTLP logs service.
OTLP_LOGS_EXPORT_PATH = "/opentelemetry.proto.collector.logs.v1.LogsService/Export"

_SCOPE_NAME = "grow-codes-graylog"


def _any_value(value: AttrValue) -> common_pb2.AnyValue:
    if isinstance(value, str):
        return common_pb2.AnyValue(string_value=value)
    if isinstance(value, bool):
        return common_pb2.AnyValue(bool_value=value)
    if isinstance(value, int):
        if -(2**63) <= value < 2**63:
            return common_pb2.AnyValue(int_value=value)
        return common_pb2.AnyValue(string_value=str(value))
    if isinstance(value, float):
        return common_pb2.AnyValue(double_value=value)
    if isinstance(value, Mapping):
        return common_pb2.AnyValue(kvlist_value=common_pb2.KeyValueList(values=_key_values(value)))
    return common_pb2.AnyValue(
        array_value=common_pb2.ArrayValue(values=[_any_value(v) for v in value])
    )


def _key_values(attrs: Mapping[str, AttrValue]) -> list[common_pb2.KeyValue]:
    return [common_pb2.KeyValue(key=str(k), value=_any_value(v)) for k, v in attrs.items()]


def _nanos(value: datetime) -> int:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return round(value.timestamp() * 1000) * 1_000_000


def encode_export_logs_request(
    records: Sequence[LogRecord],
    *,
    scope_name: str = _SCOPE_NAME,
    scope_version: str = __version__,
) -> bytes:
    """Encode records as an OTLP ``ExportLogsServiceRequest``, one ``ResourceLogs`` per resource."""
    groups: dict[str, tuple[Mapping[str, AttrValue], list[LogRecord]]] = {}
    for record in records:
        key = json.dumps(record.resource, sort_keys=True, default=str)
        groups.setdefault(key, (record.resource, []))[1].append(record)
    request = logs_service_pb2.ExportLogsServiceRequest()
    for resource, group in groups.values():
        logs = []
        for r in group:
            lr = logs_pb2.LogRecord(
                time_unix_nano=_nanos(r.timestamp),
                observed_time_unix_nano=_nanos(r.observed_timestamp or r.timestamp),
                severity_number=int(r.severity),  # type: ignore[arg-type]
                severity_text=r.severity_text,
                body=common_pb2.AnyValue(string_value=r.body),
                attributes=_key_values(r.attributes),
            )
            if r.trace_flags is not None:
                lr.flags = r.trace_flags
            if r.trace_id:
                lr.trace_id = bytes.fromhex(r.trace_id)
            if r.span_id:
                lr.span_id = bytes.fromhex(r.span_id)
            logs.append(lr)
        request.resource_logs.append(
            logs_pb2.ResourceLogs(
                resource=resource_pb2.Resource(attributes=_key_values(resource)),
                scope_logs=[
                    logs_pb2.ScopeLogs(
                        scope=common_pb2.InstrumentationScope(
                            name=scope_name, version=scope_version
                        ),
                        log_records=logs,
                    )
                ],
            )
        )
    return bytes(request.SerializeToString())


class OtlpPartialSuccess:
    """Partial success of an ``ExportLogsServiceResponse``."""

    def __init__(self, rejected_log_records: int = 0, error_message: str = "") -> None:
        self.rejected_log_records = rejected_log_records
        self.error_message = error_message


def decode_export_logs_response(data: bytes) -> OtlpPartialSuccess:
    """Decode ``partial_success``; zero values when absent or malformed."""
    try:
        resp = logs_service_pb2.ExportLogsServiceResponse.FromString(data)
    except Exception:  # noqa: BLE001 - a malformed body counts as full success
        return OtlpPartialSuccess()
    partial = resp.partial_success
    return OtlpPartialSuccess(int(partial.rejected_log_records), str(partial.error_message))


def error_for_grpc_status(status: int, message: str) -> ServiceError:
    """Map a gRPC status code to the SDK error (OTLP retryable codes are retryable)."""
    text = f"otlp.export: {message or f'gRPC status {status}'} (gRPC {status})"
    mapping: dict[int, type[ServiceError]] = {
        1: CancelledError,
        3: ValidationError,
        9: ValidationError,
        4: TimeoutError,
        5: NotFoundError,
        6: ConflictError,
        7: PermissionDeniedError,
        8: RateLimitError,
        12: UnsupportedError,
        16: AuthenticationError,
        10: UnavailableError,
        11: UnavailableError,
        14: UnavailableError,
        15: UnavailableError,
    }
    cls = mapping.get(status)
    if cls is None:
        return UnavailableError(text, retryable=False)
    return cls(text)


def _read(path: str | None) -> bytes | None:
    if not path:
        return None
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        raise ConfigError("otlp: TLS certificate files could not be loaded") from None


class OtlpGrpcLogExporter:
    """``LogExporter`` for the Graylog OpenTelemetry (gRPC) input.

    OTLP ``LogsService/Export`` over gRPC, gzip when the batch asks for it. Stored fields are
    ``otel_*``; the query client normalises them back into log records.

    Args:
        endpoint: ``http://host:4317`` (plaintext) or ``https://host:4317`` (TLS).
        bearer_token: token configured on the input; sent as ``authorization: Bearer …``.
        headers: extra gRPC metadata.
        tls: CA bundle and client certificate for ``https`` endpoints
            (``insecure_skip_verify`` is not supported by gRPC and is ignored).
        timeout_s: deadline of one export call (default 30 s).
        connect_timeout_s: how long the first call waits for the channel (default 10 s).

    Raises:
        ConfigError: for a bad endpoint or when ``grpcio`` is not installed.
    """

    def __init__(
        self,
        endpoint: str,
        *,
        bearer_token: str | Secret | None = None,
        headers: Mapping[str, str] | None = None,
        tls: TlsConfig | None = None,
        timeout_s: float = 30.0,
        connect_timeout_s: float = 10.0,
    ) -> None:
        try:
            parts = urlsplit(endpoint)
            port = parts.port
        except ValueError:
            parts, port = None, None
        if parts is None or parts.scheme not in ("http", "https") or not parts.hostname:
            raise ConfigError("otlp: endpoint must be an http(s) URL")
        if not timeout_s > 0 or not connect_timeout_s > 0:
            raise ConfigError("otlp: timeouts must be positive")
        try:
            import grpc  # noqa: PLC0415 - optional dependency
        except ImportError:  # pragma: no cover - grpcio is part of the test environment
            raise ConfigError(
                'otlp: grpcio is not installed (pip install "grow-graylog[otlp]")'
            ) from None
        self._grpc: Any = grpc
        host = parts.hostname
        self.target = f"[{host}]:{port or 4317}" if ":" in host else f"{host}:{port or 4317}"
        self.endpoint = f"{parts.scheme}://{self.target}"
        self.secure = parts.scheme == "https"
        self.timeout_s = float(timeout_s)
        self.connect_timeout_s = float(connect_timeout_s)
        self._metadata = [(k.lower(), v) for k, v in (headers or {}).items()]
        self._secrets = [v for _, v in self._metadata if len(v) >= 4]
        token = Secret(bearer_token) if bearer_token is not None else None
        if token:
            self._metadata.append(("authorization", f"Bearer {token.reveal()}"))
            self._secrets.append(token.reveal())
        self._tls = tls or TlsConfig()
        self._lock = threading.Lock()
        self._channel: Any = None
        self._call: Any = None
        self._ready = False
        self._closed = False

    def _stub(self) -> Any:
        with self._lock:
            if self._closed:
                raise ConfigError("otlp.export: exporter is closed")
            if self._call is None:
                grpc = self._grpc
                options = [("grpc.primary_user_agent", user_agent())]
                if self.secure:
                    ca = self._tls.ca_cert_pem.encode() if self._tls.ca_cert_pem else None
                    credentials = grpc.ssl_channel_credentials(
                        root_certificates=ca or _read(self._tls.ca_cert_path),
                        private_key=_read(self._tls.client_key_path),
                        certificate_chain=_read(self._tls.client_cert_path),
                    )
                    self._channel = grpc.secure_channel(self.target, credentials, options=options)
                else:
                    self._channel = grpc.insecure_channel(self.target, options=options)
                self._call = self._channel.unary_unary(OTLP_LOGS_EXPORT_PATH)
            return self._call

    def _wait_ready(self) -> None:
        if self._ready:
            return
        try:
            self._grpc.channel_ready_future(self._channel).result(timeout=self.connect_timeout_s)
        except self._grpc.FutureTimeoutError:
            raise TimeoutError(
                f"otlp.export: could not connect to {self.target} "
                f"within {self.connect_timeout_s:g}s"
            ) from None
        self._ready = True

    def export(self, records: Sequence[LogRecord], *, gzip: bool, timeout_s: float) -> ExportResult:
        """Send one batch; raises the mapped SDK error when the call fails."""
        if not records:
            return ExportResult(accepted=0)
        call = self._stub()
        self._wait_ready()
        grpc = self._grpc
        payload = encode_export_logs_request(records)
        try:
            response = call(
                payload,
                timeout=min(self.timeout_s, timeout_s) if timeout_s > 0 else self.timeout_s,
                metadata=self._metadata or None,
                compression=grpc.Compression.Gzip if gzip else grpc.Compression.NoCompression,
            )
        except grpc.RpcError as exc:
            code = exc.code()
            status = int(code.value[0]) if code is not None else 2
            raise error_for_grpc_status(status, self._redact(exc.details() or "")) from None
        partial = decode_export_logs_response(response or b"")
        rejected = min(len(records), max(0, partial.rejected_log_records))
        error: ServiceError | None = None
        if rejected:
            detail = f": {self._redact(partial.error_message)}" if partial.error_message else ""
            error = ValidationError(f"otlp.export: {rejected} records rejected{detail}")
        return ExportResult(accepted=len(records) - rejected, rejected=rejected, error=error)

    def _redact(self, text: str) -> str:
        return redact_text(text, self._secrets)[:300]

    def shutdown(self) -> None:
        """Close the channel (idempotent)."""
        with self._lock:
            self._closed = True
            channel, self._channel, self._call = self._channel, None, None
        if channel is not None:
            channel.close()

    def __repr__(self) -> str:
        return f"OtlpGrpcLogExporter(endpoint={self.endpoint!r})"
