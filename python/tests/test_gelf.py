"""GELF messages, level mapping, attribute mapping (decision 3) and read-back (decision 6)."""

from __future__ import annotations

import json
import math
import socket
from datetime import datetime, timezone

import pytest

import grow_graylog as sdk
from _fixtures import body

TS = datetime(2026, 11, 18, 11, 6, 40, 123000, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("severity", "level"),
    [
        (sdk.Severity.TRACE, 7),
        (sdk.Severity.DEBUG, 7),
        (sdk.Severity.INFO, 6),
        (11, 6),
        (sdk.Severity.WARN, 4),
        (sdk.Severity.ERROR, 3),
        (sdk.Severity.FATAL, 2),
        (0, 7),
        (99, 2),
    ],
)
def test_severity_to_level(severity: int, level: int) -> None:
    assert sdk.severity_to_gelf_level(severity) == level


@pytest.mark.parametrize(
    ("level", "severity"),
    [
        (0, sdk.Severity.FATAL),
        (2, sdk.Severity.FATAL),
        (3, sdk.Severity.ERROR),
        (4, sdk.Severity.WARN),
        (5, sdk.Severity.INFO),
        (6, sdk.Severity.INFO),
        (7, sdk.Severity.DEBUG),
        (9, sdk.Severity.DEBUG),
        (math.nan, sdk.Severity.INFO),
    ],
)
def test_level_to_severity(level: float, severity: sdk.Severity) -> None:
    assert sdk.gelf_level_to_severity(level) == severity


def test_field_key_mapping_is_ascii_only() -> None:
    assert sdk.gelf_field_key("id") == "_attr_id"
    assert sdk.gelf_field_key("service.name") == "_service.name"
    assert sdk.gelf_field_key("a b/c-d_e") == "_a_b_c-d_e"
    assert sdk.gelf_field_key("café") == "_caf_"
    assert sdk.gelf_field_key("٣") == "__"


def test_field_value_mapping() -> None:
    assert sdk.gelf_field_value("s") == "s"
    assert sdk.gelf_field_value(True) == "true"
    assert sdk.gelf_field_value(False) == "false"
    assert sdk.gelf_field_value(42) == 42
    assert sdk.gelf_field_value(1.5) == 1.5
    assert sdk.gelf_field_value(math.nan) == "NaN"
    assert sdk.gelf_field_value(math.inf) == "Infinity"
    assert sdk.gelf_field_value(-math.inf) == "-Infinity"
    assert sdk.gelf_field_value(None) is None
    assert sdk.gelf_field_value({"a": 1, "b": "x"}) == '{"a":1,"b":"x"}'
    assert sdk.gelf_field_value([1, "two"]) == '[1,"two"]'
    assert sdk.gelf_field_value(("ü",)) == '["ü"]'
    assert sdk.gelf_field_value(TS) == "2026-11-18T11:06:40.123Z"
    assert sdk.gelf_field_value(datetime(2026, 1, 1)) == "2026-01-01T00:00:00.000Z"
    assert sdk.gelf_field_value(b"x") == "b'x'"


def test_validate_field_key() -> None:
    assert sdk.validate_gelf_field_key("marker") == "_marker"
    assert sdk.validate_gelf_field_key("_a.b-c") == "_a.b-c"
    for bad in ("", "_", "a b", "é", "_id", "id"):
        with pytest.raises(sdk.ValidationError):
            sdk.validate_gelf_field_key(bad)


def test_timestamp() -> None:
    assert sdk.to_gelf_timestamp(TS) == 1795000000.123
    assert sdk.to_gelf_timestamp(datetime(1970, 1, 1, 0, 0, 1)) == 1.0


def test_message_builder() -> None:
    msg = sdk.GelfMessage(
        "h",
        "short",
        full_message="line1\nline2",
        timestamp=TS,
        level=sdk.GelfLevel.WARNING,
        fields={"marker": "m", "_n": 1, "ok": True},
    )
    msg.set_field("gone", "x").set_field("gone", None).set_field("nested", {"a": 1})
    wire = msg.to_json()
    assert wire == {
        "version": "1.1",
        "host": "h",
        "short_message": "short",
        "full_message": "line1\nline2",
        "timestamp": 1795000000.123,
        "level": 4,
        "_marker": "m",
        "_n": 1,
        "_ok": "true",
        "_nested": '{"a":1}',
    }
    assert json.loads(msg.encode()) == wire
    assert json.loads(msg.to_json_str()) == wire
    assert msg.fields["_marker"] == "m"
    assert "short" in repr(msg)
    minimal = sdk.GelfMessage("h", "m", timestamp=12)
    assert minimal.to_json() == {
        "version": "1.1",
        "host": "h",
        "short_message": "m",
        "timestamp": 12.0,
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        {"host": " ", "short_message": "m"},
        {"host": "h", "short_message": ""},
        {"host": "h", "short_message": "m", "level": 8},
        {"host": "h", "short_message": "m", "level": True},
        {"host": "h", "short_message": "m", "timestamp": math.inf},
        {"host": "h", "short_message": "m", "timestamp": "now"},
        {"host": "h", "short_message": "m", "fields": {"bad key": 1}},
    ],
)
def test_message_validation(kwargs: dict[str, object]) -> None:
    with pytest.raises(sdk.ValidationError):
        sdk.GelfMessage(**kwargs)  # type: ignore[arg-type]


def test_from_log_record_mapping() -> None:
    record = sdk.LogRecord(
        body="hello",
        severity=sdk.Severity.WARN,
        timestamp=TS,
        attributes={
            "id": "x1",
            "ok": False,
            "none": None,  # type: ignore[dict-item]
            "list": [1, 2],
            "obj": {"k": "v"},
            "": "dropped",
            "a b": 1,
        },
        resource={
            "service.name": "svc",
            "host.name": "rh",
            "deployment": {"environment": "test"},
        },
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        span_id="00f067aa0ba902b7",
        trace_flags=1,
    )
    wire = sdk.GelfMessage.from_log_record(record, host="ignored").to_json()
    assert wire["host"] == "rh"
    assert wire["short_message"] == "hello"
    assert wire["level"] == 4
    assert wire["timestamp"] == 1795000000.123
    assert wire["_service.name"] == "svc"
    assert wire["_deployment.environment"] == "test"
    assert "_host.name" not in wire
    assert wire["_attr_id"] == "x1"
    assert wire["_ok"] == "false"
    assert "_none" not in wire and "_" not in wire
    assert wire["_list"] == "[1,2]"
    assert wire["_obj"] == '{"k":"v"}'
    assert wire["_a_b"] == 1
    assert wire["_trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert wire["_span_id"] == "00f067aa0ba902b7"
    assert wire["_trace_flags"] == 1


def test_from_log_record_defaults() -> None:
    blank = sdk.LogRecord(body="  ")
    msg = sdk.GelfMessage.from_log_record(blank)
    assert msg.short_message == "-"
    assert msg.host == socket.gethostname()
    assert sdk.GelfMessage.from_log_record(blank, host="given").host == "given"
    assert sdk.GelfMessage.from_log_record(blank, host=" ").host == "unknown"


def test_flatten_attributes() -> None:
    flat = dict(sdk.flatten_attributes({"a": {"b": {"c": 1}, "d": [1]}, "e": "x"}))
    assert flat == {"a.b.c": 1, "a.d": [1], "e": "x"}


def test_read_back_gelf_fixture() -> None:
    fields = body("gelfTypedFields.stored")["message"]["message"]
    record = sdk.log_record_from_message(fields)
    assert record.body.endswith("typed")
    assert record.severity == sdk.Severity.ERROR
    assert record.resource["host.name"] == "grow-sdk-verify"
    assert record.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert record.span_id == "00f067aa0ba902b7"
    assert record.attributes["t_obj"] == '{"a":1,"b":"x"}'
    assert record.attributes["id"] == "client-id-should-be-ignored"
    assert not any(k.startswith("gl2_") for k in record.attributes)
    assert "streams" not in record.attributes
    assert record.timestamp == TS


def test_read_back_otlp_fixture() -> None:
    fields = body("otlpLogs.searched")["message"]["message"]
    record = sdk.log_record_from_message(fields)
    assert record.severity == sdk.Severity.WARN
    assert record.resource["service.name"] == "grow-sdk-verify"
    assert record.resource["marker"].startswith("growsdkotlp")
    assert record.attributes == {"attr_k": "v", "app": "server"}
    assert record.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert record.span_id == "00f067aa0ba902b7"


def test_read_back_mapping_rules() -> None:
    record = sdk.log_record_from_message(
        {
            "message": {"structured": True},
            "level": "6",
            "service_name": "svc",
            "deployment_environment": "prod",
            "deployment_environment_name": "prod2",
            "service_instance_id": "i-1",
            "attr_id": "x1",
            "trace_id": "4BF92F3577B34DA6A3CE929D0E0E4736",
            "span_id": "zz",
            "trace_flags": "1",
            "f": 1.5,
            "inf": math.inf,
            "arr": [1, None, {"a": None, "b": 2}],
            "nothing": None,
            "other": object(),
            "timestamp": "not a date",
        }
    )
    assert record.body == '{"structured":true}'
    assert record.severity == sdk.Severity.INFO
    assert record.resource == {
        "service.name": "svc",
        "deployment.environment": "prod",
        "deployment.environment.name": "prod2",
        "service.instance.id": "i-1",
    }
    assert record.attributes["id"] == "x1"
    assert record.attributes["f"] == 1.5
    assert record.attributes["inf"] == "inf"
    assert record.attributes["arr"] == [1, {"b": 2}]
    assert "nothing" not in record.attributes and "other" not in record.attributes
    assert record.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert record.span_id is None
    assert record.trace_flags == 1
    assert record.timestamp == datetime.fromtimestamp(0, timezone.utc)


@pytest.mark.parametrize(
    ("message", "text"), [(None, ""), (True, "true"), (3, "3"), (2.5, "2.5"), ("x", "x")]
)
def test_read_back_body(message: object, text: str) -> None:
    assert sdk.log_record_from_message({"message": message}).body == text


def test_read_back_severity_sources() -> None:
    assert sdk.log_record_from_message({"otel_severity_number": 17}).severity == sdk.Severity.ERROR
    assert sdk.log_record_from_message({"otel_severity_number": 0, "level": 3}).severity == (
        sdk.Severity.ERROR
    )
    assert sdk.log_record_from_message({"level": True}).severity == sdk.Severity.INFO
    no_trace = sdk.log_record_from_message({"span_id": "00f067aa0ba902b7"})
    assert no_trace.span_id is None and no_trace.trace_flags is None
    flags = sdk.log_record_from_message(
        {"otel_trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "otel_trace_flags": 1, "trace_id": 5}
    )
    assert flags.trace_flags == 1
