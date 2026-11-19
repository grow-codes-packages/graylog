import { hostname } from "node:os";
import { describe, expect, it } from "vitest";
import {
  GELF_VERSION,
  GelfLevel,
  GelfMessage,
  RESOURCE_FIELDS,
  Severity,
  flattenAttributes,
  gelfFieldKey,
  gelfFieldValue,
  gelfLevelToSeverity,
  logRecordFromMessage,
  severityToGelfLevel,
  toGelfTimestamp,
  validateGelfFieldKey,
  type LogRecord,
} from "../src/index.js";
import { loadFixture } from "./helpers/graylog.js";

function record(overrides: Partial<LogRecord> = {}): LogRecord {
  return {
    timestamp: new Date("2026-11-18T11:06:40.123Z"),
    severity: Severity.Info,
    severityText: "INFO",
    body: "hello",
    attributes: {},
    resource: {},
    ...overrides,
  };
}

describe("severity ↔ syslog level", () => {
  it("maps both ways", () => {
    expect([1, 5, 9, 13, 17, 21].map(severityToGelfLevel)).toEqual([7, 7, 6, 4, 3, 2]);
    expect(severityToGelfLevel(10)).toBe(GelfLevel.Informational);
    expect(severityToGelfLevel(24)).toBe(GelfLevel.Critical);
    expect([0, 1, 2, 3, 4, 5, 6, 7, 8].map(gelfLevelToSeverity)).toEqual([
      21, 21, 21, 17, 13, 9, 9, 5, 5,
    ]);
    expect(gelfLevelToSeverity(Number.NaN)).toBe(Severity.Info);
    expect(gelfLevelToSeverity(3.9)).toBe(Severity.Error);
  });
});

describe("attribute mapping (decision 3)", () => {
  it("keys", () => {
    expect(gelfFieldKey("user_id")).toBe("_user_id");
    expect(gelfFieldKey("service.name")).toBe("_service.name");
    expect(gelfFieldKey("a-b")).toBe("_a-b");
    expect(gelfFieldKey("a b/c:d")).toBe("_a_b_c_d");
    expect(gelfFieldKey("ünï")).toBe("__n_");
    expect(gelfFieldKey("😀x")).toBe("__x");
    expect(gelfFieldKey("id")).toBe("_attr_id");
    expect(gelfFieldKey("_id")).toBe("__id");
  });

  it("values", () => {
    expect(gelfFieldValue("s")).toBe("s");
    expect(gelfFieldValue(42)).toBe(42);
    expect(gelfFieldValue(1.5)).toBe(1.5);
    expect(gelfFieldValue(Number.POSITIVE_INFINITY)).toBe("Infinity");
    expect(gelfFieldValue(true)).toBe("true");
    expect(gelfFieldValue(false)).toBe("false");
    expect(gelfFieldValue(null)).toBeUndefined();
    expect(gelfFieldValue(undefined)).toBeUndefined();
    expect(gelfFieldValue(() => 1)).toBeUndefined();
    expect(gelfFieldValue(10n)).toBe("10");
    expect(gelfFieldValue({ a: 1, b: "x" })).toBe('{"a":1,"b":"x"}');
    expect(gelfFieldValue([1, "two"])).toBe('[1,"two"]');
    expect(gelfFieldValue(new Date("2026-01-01T00:00:00.000Z"))).toBe("2026-01-01T00:00:00.000Z");
  });

  it("explicit key validation", () => {
    expect(validateGelfFieldKey("a")).toBe("_a");
    expect(validateGelfFieldKey("_a.b-c")).toBe("_a.b-c");
    for (const bad of ["", "_", "a b", "_id", "id", "ä"]) {
      expect(() => validateGelfFieldKey(bad), bad).toThrow(/gelf:/);
    }
  });

  it("flattens nested resource attributes", () => {
    expect(flattenAttributes({ a: { b: { c: 1 } }, d: [1], e: "x" })).toEqual([
      ["a.b.c", 1],
      ["d", [1]],
      ["e", "x"],
    ]);
  });

  it("timestamps keep milliseconds", () => {
    expect(toGelfTimestamp(new Date("2026-11-18T11:06:40.123Z"))).toBe(1795000000.123);
  });
});

describe("GelfMessage", () => {
  it("builds the wire object", () => {
    const m = new GelfMessage({
      host: "web-1",
      shortMessage: "boom",
      fullMessage: "line1\nline2",
      timestamp: new Date("2026-11-18T11:06:40.123Z"),
      level: GelfLevel.Error,
      fields: { user_id: 7, ok: true, gone: null },
    })
      .setField("_request_id", "r1")
      .setField("nested", { a: 1 });
    expect(m.version).toBe(GELF_VERSION);
    expect(m.toJSON()).toEqual({
      version: "1.1",
      host: "web-1",
      short_message: "boom",
      full_message: "line1\nline2",
      timestamp: 1795000000.123,
      level: 3,
      _user_id: 7,
      _ok: "true",
      _request_id: "r1",
      _nested: '{"a":1}',
    });
    expect(m.fields).toEqual({ _user_id: 7, _ok: "true", _request_id: "r1", _nested: '{"a":1}' });
    m.setField("ok", null);
    expect(m.fields._ok).toBeUndefined();
    expect(JSON.parse(m.toString())).toEqual(m.toJSON());
    expect(Buffer.from(m.encode()).toString("utf8")).toBe(m.toString());
    expect(new GelfMessage({ host: "h", shortMessage: "s", timestamp: 12.5 }).timestamp).toBe(12.5);
    expect(new GelfMessage({ host: "h", shortMessage: "s" }).toJSON()).toEqual({
      version: "1.1",
      host: "h",
      short_message: "s",
    });
  });

  it("validates", () => {
    const bad = [
      { host: " ", shortMessage: "s" },
      { host: "h", shortMessage: "" },
      { host: "h", shortMessage: "s", level: 8 },
      { host: "h", shortMessage: "s", level: 1.5 },
      { host: "h", shortMessage: "s", timestamp: Number.NaN },
      { host: "h", shortMessage: "s", fields: { id: 1 } },
      { host: "h", shortMessage: "s", fields: { "a b": 1 } },
    ];
    for (const options of bad) {
      expect(() => new GelfMessage(options), JSON.stringify(options)).toThrow(/gelf:/);
    }
  });

  it("fromLogRecord maps resource, attributes and trace context", () => {
    const m = GelfMessage.fromLogRecord(
      record({
        severity: Severity.Warn,
        body: "hi",
        attributes: { id: "x", "a b": 1, flag: false, list: [1, 2], "": "skip" },
        resource: {
          "service.name": "svc",
          "host.name": "node-7",
          k8s: { pod: { name: "p1" } },
        },
        traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
        spanId: "00f067aa0ba902b7",
        traceFlags: 1,
      }),
    );
    expect(m.toJSON()).toEqual({
      version: "1.1",
      host: "node-7",
      short_message: "hi",
      timestamp: 1795000000.123,
      level: 4,
      "_service.name": "svc",
      "_k8s.pod.name": "p1",
      _attr_id: "x",
      _a_b: 1,
      _flag: "false",
      _list: "[1,2]",
      _trace_id: "4bf92f3577b34da6a3ce929d0e0e4736",
      _span_id: "00f067aa0ba902b7",
      _trace_flags: 1,
    });
  });

  it("fromLogRecord host fallbacks and blank bodies", () => {
    expect(GelfMessage.fromLogRecord(record(), { host: "opt" }).host).toBe("opt");
    expect(GelfMessage.fromLogRecord(record()).host).toBe(hostname() || "unknown");
    expect(GelfMessage.fromLogRecord(record(), { host: " " }).host).toBe("unknown");
    expect(GelfMessage.fromLogRecord(record({ body: "  " })).shortMessage).toBe("-");
    expect(
      GelfMessage.fromLogRecord(record({ resource: { "host.name": "" } }), { host: "x" }).host,
    ).toBe("x");
  });
});

describe("logRecordFromMessage", () => {
  it("normalises a GELF hit (dots stored as underscores)", () => {
    const r = logRecordFromMessage({
      _id: "abc",
      message: "hello",
      timestamp: "2026-11-18T21:59:12.774Z",
      level: 3,
      source: "probe-host",
      streams: ["1"],
      gl2_remote_ip: "x",
      service_name: "svc",
      deployment_environment: "test",
      run: "r1",
      attr_id: "x",
      n: 7,
      nested: { a: [1, null, "b"], c: null },
      list: [1, 2],
      trace_id: "4BF92F3577B34DA6A3CE929D0E0E4736",
      span_id: "00f067aa0ba902b7",
      trace_flags: "1",
      full_message: "long",
      odd: Number.NaN,
      nothing: null,
    });
    expect(r).toEqual({
      timestamp: new Date("2026-11-18T21:59:12.774Z"),
      severity: Severity.Error,
      severityText: "ERROR",
      body: "hello",
      attributes: {
        run: "r1",
        id: "x",
        n: 7,
        nested: { a: [1, "b"] },
        list: [1, 2],
        full_message: "long",
        odd: "NaN",
      },
      resource: {
        "host.name": "probe-host",
        "service.name": "svc",
        "deployment.environment": "test",
      },
      traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
      spanId: "00f067aa0ba902b7",
      traceFlags: 1,
    });
  });

  it("normalises the recorded GELF and OTLP fixtures", () => {
    const gelf = loadFixture("gelfTypedFields.stored").response.body as {
      message: { message: Record<string, unknown> };
    };
    const g = logRecordFromMessage(gelf.message.message);
    expect(g.severity).toBe(Severity.Error);
    expect(g.traceId).toBe("4bf92f3577b34da6a3ce929d0e0e4736");
    expect(g.attributes.t_obj).toBe('{"a":1,"b":"x"}');
    expect(g.attributes.full_message).toBe("line1\nline2");
    expect(g.attributes.id).toBe("client-id-should-be-ignored");

    const otlp = loadFixture("otlpLogs.searched").response.body as {
      message: { message: Record<string, unknown> };
    };
    const o = logRecordFromMessage(otlp.message.message);
    expect(o.severity).toBe(Severity.Warn);
    expect(o.resource["service.name"]).toBe("grow-sdk-verify");
    expect(o.resource["host.name"]).toBe("172.30.0.5");
    expect(o.attributes).toEqual({ attr_k: "v", app: "server" });
  });

  it("defaults for sparse or odd hits", () => {
    const r = logRecordFromMessage({ message: 5, otel_severity_number: 99, level: "4" });
    expect(r.timestamp.getTime()).toBe(0);
    expect(r.body).toBe("5");
    expect(r.severity).toBe(Severity.Warn);
    expect(r.traceId).toBeUndefined();
    const s = logRecordFromMessage({
      otel_severity_number: 17,
      trace_id: "nothex",
      span_id: "00f067aa0ba902b7",
    });
    expect(s.severity).toBe(Severity.Error);
    expect(s.body).toBe("");
    expect(s.traceId).toBeUndefined();
    const t = logRecordFromMessage({ trace_id: "4bf92f3577b34da6a3ce929d0e0e4736", level: "x" });
    expect(t.traceId).toBe("4bf92f3577b34da6a3ce929d0e0e4736");
    expect(t.spanId).toBeUndefined();
    expect(t.traceFlags).toBeUndefined();
    expect(t.severity).toBe(Severity.Info);
    expect(RESOURCE_FIELDS.service_name).toBe("service.name");
  });

  it("round-trips a record through the GELF mapping (as Graylog stores it)", () => {
    const original = record({
      severity: Severity.Error,
      severityText: "ERROR",
      attributes: { request_id: "r", n: 1, id: "i" },
      resource: { "service.name": "svc", "host.name": "h" },
      traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
      spanId: "00f067aa0ba902b7",
    });
    const wire = GelfMessage.fromLogRecord(original).toJSON() as unknown as Record<string, unknown>;
    // what Graylog stores: no leading underscore, dots → underscores
    const stored: Record<string, unknown> = {
      message: wire.short_message,
      source: wire.host,
      level: wire.level,
      timestamp: new Date((wire.timestamp as number) * 1000).toISOString(),
    };
    for (const [k, v] of Object.entries(wire)) {
      if (k.startsWith("_")) stored[k.slice(1).replaceAll(".", "_")] = v;
    }
    const back = logRecordFromMessage(stored);
    expect(back).toEqual({
      ...original,
      resource: { "host.name": "h", "service.name": "svc" },
    });
  });
});
