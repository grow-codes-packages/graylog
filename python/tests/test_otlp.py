"""OTLP/gRPC logs exporter against an in-process gRPC server (raw bytes handler)."""

from __future__ import annotations

import socket
from collections.abc import Iterator
from concurrent import futures
from datetime import datetime, timezone
from typing import Any

import grpc
import pytest
from opentelemetry.proto.collector.logs.v1 import logs_service_pb2

import grow_graylog as sdk

TS = datetime(2026, 11, 18, 11, 6, 40, 123000, tzinfo=timezone.utc)


class Collector:
    """Generic gRPC server for ``LogsService/Export``; behaviour set per test."""

    def __init__(self) -> None:
        self.requests: list[logs_service_pb2.ExportLogsServiceRequest] = []
        self.metadata: list[dict[str, str]] = []
        self.reply: bytes = b""
        self.abort: tuple[grpc.StatusCode, str] | None = None
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))

        def export(request: bytes, context: grpc.ServicerContext) -> bytes:
            self.requests.append(logs_service_pb2.ExportLogsServiceRequest.FromString(request))
            self.metadata.append(dict(context.invocation_metadata()))  # type: ignore[arg-type]
            if self.abort is not None:
                context.abort(*self.abort)
            return self.reply

        handler = grpc.method_handlers_generic_handler(
            "opentelemetry.proto.collector.logs.v1.LogsService",
            {"Export": grpc.unary_unary_rpc_method_handler(export)},
        )
        self.server.add_generic_rpc_handlers((handler,))
        self.port = self.server.add_insecure_port("127.0.0.1:0")
        self.server.start()

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}"


@pytest.fixture
def collector() -> Iterator[Collector]:
    c = Collector()
    yield c
    c.server.stop(None)


def record(**kw: Any) -> sdk.LogRecord:
    values: dict[str, Any] = {
        "body": "hello",
        "severity": sdk.Severity.WARN,
        "timestamp": TS,
        "attributes": {
            "s": "x",
            "b": True,
            "i": 7,
            "f": 1.5,
            "big": 2**70,
            "l": [1, "a"],
            "m": {"k": "v"},
        },
        "resource": {"service.name": "svc"},
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
        "span_id": "00f067aa0ba902b7",
        "trace_flags": 1,
    }
    values.update(kw)
    return sdk.LogRecord(**values)


def test_encode_groups_by_resource() -> None:
    data = sdk.encode_export_logs_request(
        [record(), record(body="two"), record(resource={"service.name": "other"})]
    )
    req = logs_service_pb2.ExportLogsServiceRequest.FromString(data)
    assert len(req.resource_logs) == 2
    first = req.resource_logs[0]
    assert first.resource.attributes[0].key == "service.name"
    assert first.scope_logs[0].scope.name == "grow-codes-graylog"
    lr = first.scope_logs[0].log_records[0]
    assert lr.body.string_value == "hello"
    assert lr.severity_number == 13 and lr.severity_text == "WARN"
    assert lr.time_unix_nano == 1795000000123000000
    assert lr.observed_time_unix_nano == lr.time_unix_nano
    assert lr.trace_id.hex() == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert lr.span_id.hex() == "00f067aa0ba902b7"
    assert lr.flags == 1
    attrs = {kv.key: kv.value for kv in lr.attributes}
    assert attrs["s"].string_value == "x"
    assert attrs["b"].bool_value is True
    assert attrs["i"].int_value == 7
    assert attrs["f"].double_value == 1.5
    assert attrs["big"].string_value == str(2**70)
    assert [v.int_value for v in attrs["l"].array_value.values][:1] == [1]
    assert attrs["m"].kvlist_value.values[0].key == "k"
    plain = sdk.encode_export_logs_request(
        [sdk.LogRecord(body="x", timestamp=datetime(2026, 1, 1))], scope_version="9"
    )
    lr2 = logs_service_pb2.ExportLogsServiceRequest.FromString(plain).resource_logs[0]
    assert lr2.scope_logs[0].scope.version == "9"
    assert not lr2.scope_logs[0].log_records[0].trace_id


def test_decode_response() -> None:
    resp = logs_service_pb2.ExportLogsServiceResponse()
    resp.partial_success.rejected_log_records = 2
    resp.partial_success.error_message = "bad"
    partial = sdk.decode_export_logs_response(resp.SerializeToString())
    assert (partial.rejected_log_records, partial.error_message) == (2, "bad")
    junk = sdk.decode_export_logs_response(b"\xff\xff\xff")
    assert junk.rejected_log_records == 0


@pytest.mark.parametrize(
    ("status", "cls"),
    [
        (1, sdk.CancelledError),
        (3, sdk.ValidationError),
        (4, sdk.TimeoutError),
        (5, sdk.NotFoundError),
        (6, sdk.ConflictError),
        (7, sdk.PermissionDeniedError),
        (8, sdk.RateLimitError),
        (9, sdk.ValidationError),
        (12, sdk.UnsupportedError),
        (14, sdk.UnavailableError),
        (16, sdk.AuthenticationError),
        (13, sdk.UnavailableError),
    ],
)
def test_grpc_status_mapping(status: int, cls: type[sdk.GraylogError]) -> None:
    err = sdk.error_for_grpc_status(status, "")
    assert isinstance(err, cls)
    assert f"(gRPC {status})" in err.message
    if status == 13:
        assert err.retryable is False
    if status == 14:
        assert err.retryable is True


def test_export_success_with_token_and_gzip(collector: Collector) -> None:
    exporter = sdk.OtlpGrpcLogExporter(
        collector.endpoint,
        bearer_token="bearer-secret-1",
        headers={"X-Tenant": "t1"},
        timeout_s=5,
    )
    assert exporter.export([], gzip=True, timeout_s=5).accepted == 0
    result = exporter.export([record(), record(body="b")], gzip=True, timeout_s=5)
    assert (result.accepted, result.rejected, result.error) == (2, 0, None)
    meta = collector.metadata[0]
    assert meta["authorization"] == "Bearer bearer-secret-1"
    assert meta["x-tenant"] == "t1"
    assert "grow-codes-graylog" in meta["user-agent"]
    assert (
        collector.requests[0].resource_logs[0].scope_logs[0].log_records[1].body.string_value == "b"
    )
    exporter.export([record()], gzip=False, timeout_s=0)
    assert "bearer-secret-1" not in repr(exporter)
    exporter.shutdown()
    exporter.shutdown()
    with pytest.raises(sdk.ConfigError):
        exporter.export([record()], gzip=False, timeout_s=1)


def test_export_partial_success(collector: Collector) -> None:
    resp = logs_service_pb2.ExportLogsServiceResponse()
    resp.partial_success.rejected_log_records = 5
    resp.partial_success.error_message = "token tok-12345 rejected"
    collector.reply = resp.SerializeToString()
    exporter = sdk.OtlpGrpcLogExporter(collector.endpoint, headers={"x-key": "tok-12345"})
    result = exporter.export([record(), record()], gzip=False, timeout_s=5)
    assert (result.accepted, result.rejected) == (0, 2)
    assert isinstance(result.error, sdk.ValidationError)
    assert "tok-12345" not in str(result.error)
    resp.partial_success.error_message = ""
    resp.partial_success.rejected_log_records = 1
    collector.reply = resp.SerializeToString()
    other = exporter.export([record(), record()], gzip=False, timeout_s=5)
    assert other.rejected == 1 and str(other.error).endswith("1 records rejected")
    exporter.shutdown()


def test_export_status_errors(collector: Collector) -> None:
    collector.abort = (grpc.StatusCode.UNAUTHENTICATED, "bad bearer-secret-2")
    exporter = sdk.OtlpGrpcLogExporter(collector.endpoint, bearer_token="bearer-secret-2")
    with pytest.raises(sdk.AuthenticationError) as info:
        exporter.export([record()], gzip=False, timeout_s=5)
    assert "bearer-secret-2" not in str(info.value)
    collector.abort = (grpc.StatusCode.RESOURCE_EXHAUSTED, "")
    with pytest.raises(sdk.RateLimitError, match="gRPC status 8"):
        exporter.export([record()], gzip=False, timeout_s=5)
    exporter.shutdown()


def test_connect_timeout() -> None:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    exporter = sdk.OtlpGrpcLogExporter(f"http://127.0.0.1:{port}", connect_timeout_s=0.2)
    with pytest.raises(sdk.TimeoutError, match="could not connect"):
        exporter.export([record()], gzip=False, timeout_s=1)
    exporter.shutdown()


def test_secure_channel_setup(tmp_path: Any) -> None:
    exporter = sdk.OtlpGrpcLogExporter(
        "https://[::1]",
        tls=sdk.TlsConfig(ca_cert_pem="-----BEGIN CERTIFICATE-----"),
    )
    assert exporter.secure and exporter.target == "[::1]:4317"
    exporter._stub()
    exporter.shutdown()
    missing = sdk.OtlpGrpcLogExporter(
        "https://h:1", tls=sdk.TlsConfig(ca_cert_path=str(tmp_path / "none.pem"))
    )
    with pytest.raises(sdk.ConfigError):
        missing._stub()
    pem = tmp_path / "ca.pem"
    pem.write_text("x")
    ok = sdk.OtlpGrpcLogExporter("https://h:1", tls=sdk.TlsConfig(ca_cert_path=str(pem)))
    ok._stub()
    ok.shutdown()


@pytest.mark.parametrize(
    ("endpoint", "kwargs"),
    [
        ("grpc://h:4317", {}),
        ("http://", {}),
        ("http://h:99999", {}),
        ("http://h:4317", {"timeout_s": 0}),
        ("http://h:4317", {"connect_timeout_s": -1}),
    ],
)
def test_validation(endpoint: str, kwargs: dict[str, Any]) -> None:
    with pytest.raises(sdk.ConfigError):
        sdk.OtlpGrpcLogExporter(endpoint, **kwargs)
