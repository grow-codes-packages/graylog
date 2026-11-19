// Service-owned: GELF 1.1 messages, severity ↔ syslog level mapping and the attribute mapping
// shared by every GELF transport (coordinator decision 3, identical in all five languages).

import { hostname } from "node:os";
import { ValidationError } from "./core/index.js";
import {
  Severity,
  canonicalSeverity,
  severityText,
  type AttrValue,
  type Attributes,
  type LogRecord,
} from "./logging/index.js";

/** GELF specification version written into every message. */
export const GELF_VERSION = "1.1";

/** Syslog severity levels used by the GELF `level` field. */
export enum GelfLevel {
  Emergency = 0,
  Alert = 1,
  Critical = 2,
  Error = 3,
  Warning = 4,
  Notice = 5,
  Informational = 6,
  Debug = 7,
}

/** A GELF additional field value as written on the wire. */
export type GelfFieldValue = string | number;

/** The GELF wire object. */
export interface GelfPayload {
  version: string;
  host: string;
  short_message: string;
  full_message?: string;
  timestamp?: number;
  level?: number;
  [field: `_${string}`]: GelfFieldValue;
}

/**
 * OTel severity → syslog level: TRACE/DEBUG → 7, INFO → 6, WARN → 4, ERROR → 3, FATAL → 2.
 * Numbers between the named values use the range they fall into.
 */
export function severityToGelfLevel(severity: number): GelfLevel {
  switch (canonicalSeverity(severity)) {
    case Severity.Trace:
    case Severity.Debug:
      return GelfLevel.Debug;
    case Severity.Warn:
      return GelfLevel.Warning;
    case Severity.Error:
      return GelfLevel.Error;
    case Severity.Fatal:
      return GelfLevel.Critical;
    default:
      return GelfLevel.Informational;
  }
}

/** Syslog level → OTel severity: 0–2 → FATAL, 3 → ERROR, 4 → WARN, 5–6 → INFO, 7 → DEBUG. */
export function gelfLevelToSeverity(level: number): Severity {
  if (!Number.isFinite(level)) return Severity.Info;
  const n = Math.trunc(level);
  if (n <= 2) return Severity.Fatal;
  if (n === 3) return Severity.Error;
  if (n === 4) return Severity.Warn;
  if (n >= 7) return Severity.Debug;
  return Severity.Info;
}

const KEY_CHARS = /^[\w.-]+$/;
const KEY_SANITIZE = /[^\w.-]/gu;

/**
 * Maps an attribute name to its GELF additional field key (decision 3): `_` prefix, every character
 * outside `[A-Za-z0-9_.-]` becomes `_`, and `id` (reserved by GELF) becomes `_attr_id`.
 */
export function gelfFieldKey(name: string): `_${string}` {
  if (name === "id") return "_attr_id";
  return `_${name.replace(KEY_SANITIZE, "_")}`;
}

/**
 * Maps an attribute value to its GELF form (decision 3): strings and finite numbers unchanged,
 * booleans → `"true"`/`"false"`, `null`/`undefined` → omitted (`undefined`), other numbers →
 * their text, arrays and objects → compact JSON strings.
 */
export function gelfFieldValue(value: unknown): GelfFieldValue | undefined {
  switch (typeof value) {
    case "string":
      return value;
    case "number":
      return Number.isFinite(value) ? value : String(value);
    case "boolean":
      return value ? "true" : "false";
    case "bigint":
      return value.toString();
    case "object":
      if (value === null) return undefined;
      if (value instanceof Date) return value.toISOString();
      return JSON.stringify(value);
    default:
      return undefined;
  }
}

/**
 * Validates an explicit additional field key for {@link GelfMessage.setField}. Accepts `name` or
 * `_name`; returns the `_name` wire key. Throws {@link ValidationError} for keys outside
 * `[A-Za-z0-9_.-]`, empty keys and the reserved `id`.
 */
export function validateGelfFieldKey(key: string): `_${string}` {
  const name = key.startsWith("_") ? key.slice(1) : key;
  if (name === "" || !KEY_CHARS.test(name)) {
    throw new ValidationError(
      `gelf: invalid additional field key ${JSON.stringify(key)} (allowed: letters, digits, _ . -)`,
    );
  }
  if (name === "id") {
    throw new ValidationError('gelf: additional field "_id" is reserved');
  }
  return `_${name}`;
}

/** Unix seconds with millisecond precision. */
export function toGelfTimestamp(date: Date): number {
  return Math.round(date.getTime()) / 1000;
}

/** Options of {@link GelfMessage}. */
export interface GelfMessageOptions {
  /** Source host (stored as `source`). Required, not blank. */
  host: string;
  /** Short message (stored as `message`). Required, not blank. */
  shortMessage: string;
  /** Long message (e.g. a stack trace). */
  fullMessage?: string;
  /** Event time: a `Date` or Unix seconds. */
  timestamp?: Date | number;
  /** Syslog level 0–7. */
  level?: GelfLevel | number;
  /** Additional fields; keys are validated like {@link GelfMessage.setField}. */
  fields?: Readonly<Record<string, unknown>>;
}

/** Options of {@link GelfMessage.fromLogRecord}. */
export interface FromLogRecordOptions {
  /** Host used when the record has no `resource["host.name"]`. Default: `os.hostname()`. */
  host?: string;
}

/**
 * One GELF 1.1 message. Build it with the constructor and {@link setField}, or from a
 * {@link LogRecord} with {@link fromLogRecord}; serialise with {@link toJSON} / {@link encode}.
 */
export class GelfMessage {
  /** Always `"1.1"`. */
  readonly version = GELF_VERSION;
  readonly host: string;
  readonly shortMessage: string;
  readonly fullMessage?: string;
  /** Unix seconds (millisecond precision). */
  readonly timestamp?: number;
  /** Syslog level 0–7. */
  readonly level?: number;
  readonly #fields = new Map<`_${string}`, GelfFieldValue>();

  /** Validates the options; throws {@link ValidationError}. */
  constructor(options: GelfMessageOptions) {
    if (typeof options.host !== "string" || options.host.trim() === "") {
      throw new ValidationError("gelf: host must not be blank");
    }
    if (typeof options.shortMessage !== "string" || options.shortMessage.trim() === "") {
      throw new ValidationError("gelf: shortMessage must not be blank");
    }
    this.host = options.host;
    this.shortMessage = options.shortMessage;
    if (options.fullMessage !== undefined) this.fullMessage = options.fullMessage;
    if (options.timestamp !== undefined) {
      const ts =
        options.timestamp instanceof Date ? toGelfTimestamp(options.timestamp) : options.timestamp;
      if (!Number.isFinite(ts)) throw new ValidationError("gelf: invalid timestamp");
      this.timestamp = ts;
    }
    if (options.level !== undefined) {
      if (!Number.isInteger(options.level) || options.level < 0 || options.level > 7) {
        throw new ValidationError("gelf: level must be an integer 0..7");
      }
      this.level = options.level;
    }
    for (const [k, v] of Object.entries(options.fields ?? {})) this.setField(k, v);
  }

  /**
   * Sets an additional field (`name` or `_name`). The key is validated
   * ({@link validateGelfFieldKey}); the value is mapped by {@link gelfFieldValue} and a `null`
   * value removes the field. Returns `this` for chaining.
   */
  setField(key: string, value: unknown): this {
    const wireKey = validateGelfFieldKey(key);
    const mapped = gelfFieldValue(value);
    if (mapped === undefined) this.#fields.delete(wireKey);
    else this.#fields.set(wireKey, mapped);
    return this;
  }

  /** Additional fields with their `_` keys. */
  get fields(): Readonly<Record<string, GelfFieldValue>> {
    return Object.fromEntries(this.#fields);
  }

  /**
   * Converts a log record (decision 3): `host` = `resource["host.name"]` (else `options.host`,
   * else `os.hostname()`), `short_message` = body (`"-"` when blank), `timestamp`, `level` from the
   * severity, resource attributes flattened with dotted keys (except `host.name`), then the record
   * attributes, then `_trace_id`, `_span_id`, `_trace_flags`. Keys are sanitised with
   * {@link gelfFieldKey}, values mapped with {@link gelfFieldValue}.
   */
  static fromLogRecord(record: LogRecord, options: FromLogRecordOptions = {}): GelfMessage {
    const resourceHost = record.resource["host.name"];
    const host =
      typeof resourceHost === "string" && resourceHost.trim() !== ""
        ? resourceHost
        : (options.host ?? hostname());
    const msg = new GelfMessage({
      host: host.trim() === "" ? "unknown" : host,
      shortMessage: record.body.trim() === "" ? "-" : record.body,
      timestamp: record.timestamp,
      level: severityToGelfLevel(record.severity),
    });
    const put = (name: string, value: unknown): void => {
      if (name === "") return;
      const v = gelfFieldValue(value);
      if (v !== undefined) msg.#fields.set(gelfFieldKey(name), v);
    };
    for (const [k, v] of flattenAttributes(record.resource)) {
      if (k !== "host.name") put(k, v);
    }
    for (const [k, v] of Object.entries(record.attributes)) put(k, v);
    if (record.traceId !== undefined) put("trace_id", record.traceId);
    if (record.spanId !== undefined) put("span_id", record.spanId);
    if (record.traceFlags !== undefined) put("trace_flags", record.traceFlags);
    return msg;
  }

  /** The GELF wire object. */
  toJSON(): GelfPayload {
    const out: GelfPayload = {
      version: this.version,
      host: this.host,
      short_message: this.shortMessage,
    };
    if (this.fullMessage !== undefined) out.full_message = this.fullMessage;
    if (this.timestamp !== undefined) out.timestamp = this.timestamp;
    if (this.level !== undefined) out.level = this.level;
    for (const [k, v] of this.#fields) out[k] = v;
    return out;
  }

  /** Compact JSON text. */
  toString(): string {
    return JSON.stringify(this.toJSON());
  }

  /** UTF-8 JSON bytes. */
  encode(): Uint8Array {
    return Buffer.from(this.toString(), "utf8");
  }
}

/** Flattens nested objects into dotted keys; arrays and scalars are leaves. */
export function flattenAttributes(attributes: Attributes, prefix = ""): [string, AttrValue][] {
  const out: [string, AttrValue][] = [];
  for (const [k, v] of Object.entries(attributes)) {
    const key = prefix === "" ? k : `${prefix}.${k}`;
    if (typeof v === "object" && !Array.isArray(v)) {
      out.push(...flattenAttributes(v, key));
    } else {
      out.push([key, v]);
    }
  }
  return out;
}

// ---- search hit → LogRecord ---------------------------------------------------------------

/**
 * Stored field names (Graylog replaces `.` by `_` in field names) that map back to OTel resource
 * keys.
 */
export const RESOURCE_FIELDS: Readonly<Record<string, string>> = Object.freeze({
  service_name: "service.name",
  service_version: "service.version",
  service_namespace: "service.namespace",
  service_instance_id: "service.instance.id",
  deployment_environment: "deployment.environment",
  deployment_environment_name: "deployment.environment.name",
});

/** Stored fields that are never copied into attributes. */
const SKIPPED_FIELDS: ReadonlySet<string> = new Set([
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
]);

const HEX32 = /^[0-9a-f]{32}$/;
const HEX16 = /^[0-9a-f]{16}$/;

function asString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function asNumber(v: unknown): number | undefined {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^-?\d+(\.\d+)?$/.test(v.trim())) return Number(v);
  return undefined;
}

function hexId(v: unknown, re: RegExp): string | undefined {
  const s = asString(v)?.trim().toLowerCase();
  return s !== undefined && re.test(s) ? s : undefined;
}

function attrValue(v: unknown): AttrValue | undefined {
  if (typeof v === "string" || typeof v === "boolean") return v;
  if (typeof v === "number") return Number.isFinite(v) ? v : String(v);
  if (v === null || v === undefined) return undefined;
  if (Array.isArray(v)) {
    return v.map(attrValue).filter((x): x is AttrValue => x !== undefined);
  }
  if (typeof v === "object") {
    const out: Attributes = {};
    for (const [k, inner] of Object.entries(v)) {
      const a = attrValue(inner);
      if (a !== undefined) out[k] = a;
    }
    return out;
  }
  return typeof v === "bigint" ? v.toString() : undefined;
}

function bodyText(v: unknown): string {
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return v === undefined || v === null ? "" : JSON.stringify(v);
}

/**
 * Normalises a stored Graylog message (search hit or `getMessage` fields) into a {@link LogRecord}.
 * OTLP fields (`otel_*`) win over GELF fields. `source` → `resource["host.name"]`, known resource
 * fields ({@link RESOURCE_FIELDS}) and `otel_resource_attributes_*` → resource, `attr_id` → `id`,
 * `otel_attributes_*` and every other field except `gl2_*` and the reserved ones → attributes.
 */
export function logRecordFromMessage(fields: Readonly<Record<string, unknown>>): LogRecord {
  const ts = asString(fields.timestamp);
  const parsed = ts === undefined ? Number.NaN : Date.parse(ts);
  const otelSeverity = asNumber(fields.otel_severity_number);
  const level = asNumber(fields.level);
  let severity: Severity;
  if (otelSeverity !== undefined && otelSeverity >= 1 && otelSeverity <= 24) {
    severity = canonicalSeverity(otelSeverity);
  } else if (level !== undefined) {
    severity = gelfLevelToSeverity(level);
  } else {
    severity = Severity.Info;
  }
  const record: LogRecord = {
    timestamp: new Date(Number.isNaN(parsed) ? 0 : parsed),
    severity,
    severityText: severityText(severity),
    body: bodyText(fields.message),
    attributes: {},
    resource: {},
  };
  const source = asString(fields.source);
  if (source !== undefined && source !== "") record.resource["host.name"] = source;
  for (const [key, value] of Object.entries(fields)) {
    if (SKIPPED_FIELDS.has(key) || key.startsWith("gl2_")) continue;
    const v = attrValue(value);
    if (v === undefined) continue;
    if (key.startsWith("otel_resource_attributes_")) {
      const name = key.slice("otel_resource_attributes_".length);
      record.resource[RESOURCE_FIELDS[name] ?? name] = v;
    } else if (key.startsWith("otel_attributes_")) {
      record.attributes[key.slice("otel_attributes_".length)] = v;
    } else if (RESOURCE_FIELDS[key] !== undefined) {
      record.resource[RESOURCE_FIELDS[key]] ??= v;
    } else if (key === "attr_id") {
      record.attributes.id = v;
    } else {
      record.attributes[key] = v;
    }
  }
  const traceId = hexId(fields.otel_trace_id, HEX32) ?? hexId(fields.trace_id, HEX32);
  if (traceId !== undefined) {
    record.traceId = traceId;
    const spanId = hexId(fields.otel_span_id, HEX16) ?? hexId(fields.span_id, HEX16);
    if (spanId !== undefined) record.spanId = spanId;
    const flags = asNumber(fields.otel_trace_flags) ?? asNumber(fields.trace_flags);
    if (flags !== undefined) record.traceFlags = flags;
  }
  return record;
}
