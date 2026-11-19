// Service-owned: optional OTLP/gRPC logs exporter for the Graylog OpenTelemetry (gRPC) input.
// Graylog Open 7.0 has no OTLP/HTTP input, so this speaks gRPC over HTTP/2 (node:http2) with a
// small hand-written protobuf encoder (no runtime dependency).

import { connect, constants, type ClientHttp2Session } from "node:http2";
import { gzipSync } from "node:zlib";
import {
  AuthenticationError,
  CancelledError,
  ConfigError,
  ConflictError,
  type GraylogError,
  NotFoundError,
  PermissionDeniedError,
  RateLimitError,
  Secret,
  TimeoutError,
  UnavailableError,
  UnsupportedError,
  ValidationError,
  redactText,
  LANGUAGE,
  PACKAGE_KEY,
  SDK_VERSION,
} from "./core/index.js";
import { tlsConnectOptions, type GelfTlsOptions } from "./gelf-transports.js";
import type {
  AttrValue,
  Attributes,
  ExportOptions,
  ExportResult,
  LogExporter,
  LogRecord,
} from "./logging/index.js";

/** gRPC method path of the OTLP logs service. */
export const OTLP_LOGS_EXPORT_PATH = "/opentelemetry.proto.collector.logs.v1.LogsService/Export";

// ---- protobuf writer ------------------------------------------------------------------------

/** Minimal protobuf writer (varint, fixed32/64, double, length-delimited). @internal */
export class ProtoWriter {
  readonly #parts: Uint8Array[] = [];
  #length = 0;

  #push(bytes: Uint8Array): void {
    this.#parts.push(bytes);
    this.#length += bytes.length;
  }

  #varint(value: bigint): void {
    const out: number[] = [];
    let v = BigInt.asUintN(64, value);
    while (v >= 0x80n) {
      out.push(Number(v & 0x7fn) | 0x80);
      v >>= 7n;
    }
    out.push(Number(v));
    this.#push(Uint8Array.from(out));
  }

  #tag(field: number, wire: number): void {
    this.#varint(BigInt((field << 3) | wire));
  }

  /** Varint field (int64/uint32/enum/bool). */
  varint(field: number, value: number | bigint | boolean): this {
    this.#tag(field, 0);
    this.#varint(typeof value === "boolean" ? (value ? 1n : 0n) : BigInt(value));
    return this;
  }

  /** fixed64 field. */
  fixed64(field: number, value: bigint): this {
    this.#tag(field, 1);
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(BigInt.asUintN(64, value));
    this.#push(b);
    return this;
  }

  /** fixed32 field. */
  fixed32(field: number, value: number): this {
    this.#tag(field, 5);
    const b = Buffer.alloc(4);
    b.writeUInt32LE(value >>> 0);
    this.#push(b);
    return this;
  }

  /** double field. */
  double(field: number, value: number): this {
    this.#tag(field, 1);
    const b = Buffer.alloc(8);
    b.writeDoubleLE(value);
    this.#push(b);
    return this;
  }

  /** bytes field. */
  bytes(field: number, value: Uint8Array): this {
    this.#tag(field, 2);
    this.#varint(BigInt(value.length));
    this.#push(value);
    return this;
  }

  /** string field. */
  string(field: number, value: string): this {
    return this.bytes(field, Buffer.from(value, "utf8"));
  }

  /** Embedded message field. */
  message(field: number, build: (w: ProtoWriter) => void): this {
    const inner = new ProtoWriter();
    build(inner);
    return this.bytes(field, inner.finish());
  }

  /** The encoded bytes. */
  finish(): Uint8Array {
    return Buffer.concat(this.#parts, this.#length);
  }
}

function writeAnyValue(w: ProtoWriter, value: AttrValue): void {
  if (typeof value === "string") w.string(1, value);
  else if (typeof value === "boolean") w.varint(2, value);
  else if (typeof value === "number") {
    if (Number.isSafeInteger(value)) w.varint(3, value);
    else w.double(4, value);
  } else if (Array.isArray(value)) {
    w.message(5, (arr) => {
      for (const item of value)
        arr.message(1, (iv) => {
          writeAnyValue(iv, item);
        });
    });
  } else {
    w.message(6, (kvl) => {
      for (const [k, v] of Object.entries(value))
        kvl.message(1, (kv) => {
          writeKeyValue(kv, k, v);
        });
    });
  }
}

function writeKeyValue(w: ProtoWriter, key: string, value: AttrValue): void {
  w.string(1, key);
  w.message(2, (av) => {
    writeAnyValue(av, value);
  });
}

function nanos(date: Date): bigint {
  return BigInt(Math.round(date.getTime())) * 1_000_000n;
}

/** Encodes records as an OTLP `ExportLogsServiceRequest`, one `ResourceLogs` per distinct resource. */
export function encodeExportLogsRequest(
  records: readonly LogRecord[],
  scope: { name: string; version: string } = {
    name: `grow-codes-${PACKAGE_KEY}`,
    version: SDK_VERSION,
  },
): Uint8Array {
  const groups = new Map<string, { resource: Attributes; records: LogRecord[] }>();
  for (const record of records) {
    const key = JSON.stringify(record.resource);
    let group = groups.get(key);
    if (group === undefined) {
      group = { resource: record.resource, records: [] };
      groups.set(key, group);
    }
    group.records.push(record);
  }
  const w = new ProtoWriter();
  for (const group of groups.values()) {
    w.message(1, (rl) => {
      rl.message(1, (res) => {
        for (const [k, v] of Object.entries(group.resource))
          res.message(1, (kv) => {
            writeKeyValue(kv, k, v);
          });
      });
      rl.message(2, (sl) => {
        sl.message(1, (sc) => sc.string(1, scope.name).string(2, scope.version));
        for (const r of group.records) {
          sl.message(2, (lr) => {
            lr.fixed64(1, nanos(r.timestamp));
            lr.varint(2, r.severity);
            lr.string(3, r.severityText);
            lr.message(5, (av) => av.string(1, r.body));
            for (const [k, v] of Object.entries(r.attributes))
              lr.message(6, (kv) => {
                writeKeyValue(kv, k, v);
              });
            if (r.traceFlags !== undefined) lr.fixed32(8, r.traceFlags);
            if (r.traceId !== undefined) lr.bytes(9, Buffer.from(r.traceId, "hex"));
            if (r.spanId !== undefined) lr.bytes(10, Buffer.from(r.spanId, "hex"));
            lr.fixed64(11, nanos(r.observedTimestamp ?? r.timestamp));
          });
        }
      });
    });
  }
  return w.finish();
}

// ---- protobuf reader (response) -------------------------------------------------------------

function readVarint(buf: Uint8Array, pos: number): [bigint, number] {
  let result = 0n;
  let shift = 0n;
  for (;;) {
    if (pos >= buf.length) throw new Error("truncated varint");
    const b = buf[pos++] as number;
    result |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) return [result, pos];
    shift += 7n;
  }
}

/** Iterates `[field, wireType, value]` of a protobuf message (varint → bigint, len → bytes). */
function* fields(buf: Uint8Array): Generator<[number, number, bigint | Uint8Array]> {
  let pos = 0;
  while (pos < buf.length) {
    const [tag, p1] = readVarint(buf, pos);
    pos = p1;
    const field = Number(tag >> 3n);
    const wire = Number(tag & 7n);
    if (wire === 0) {
      const [v, p2] = readVarint(buf, pos);
      pos = p2;
      yield [field, wire, v];
    } else if (wire === 2) {
      const [len, p2] = readVarint(buf, pos);
      const end = p2 + Number(len);
      if (end > buf.length) throw new Error("truncated field");
      yield [field, wire, buf.subarray(p2, end)];
      pos = end;
    } else if (wire === 1) {
      pos += 8;
    } else if (wire === 5) {
      pos += 4;
    } else {
      throw new Error(`unsupported wire type ${wire}`);
    }
  }
}

/** Partial success of an `ExportLogsServiceResponse`. */
export interface OtlpPartialSuccess {
  rejectedLogRecords: number;
  errorMessage: string;
}

/** Decodes `ExportLogsServiceResponse.partial_success`; zero values when absent or malformed. */
export function decodeExportLogsResponse(buf: Uint8Array): OtlpPartialSuccess {
  const out: OtlpPartialSuccess = { rejectedLogRecords: 0, errorMessage: "" };
  try {
    for (const [field, wire, value] of fields(buf)) {
      if (field !== 1 || wire !== 2) continue;
      for (const [f, w, v] of fields(value as Uint8Array)) {
        if (f === 1 && w === 0) out.rejectedLogRecords = Number(v);
        if (f === 2 && w === 2) out.errorMessage = Buffer.from(v as Uint8Array).toString("utf8");
      }
    }
  } catch {
    // a malformed response body is treated as full success
  }
  return out;
}

// ---- gRPC status mapping --------------------------------------------------------------------

/** Maps a gRPC status code to the SDK error (OTLP retryable codes are retryable). */
export function errorForGrpcStatus(status: number, message: string): GraylogError {
  const text = `otlp.export: ${message === "" ? `gRPC status ${status}` : message} (gRPC ${status})`;
  switch (status) {
    case 1:
      return new CancelledError(text);
    case 3:
    case 9:
      return new ValidationError(text);
    case 4:
      return new TimeoutError(text);
    case 5:
      return new NotFoundError(text);
    case 6:
      return new ConflictError(text);
    case 7:
      return new PermissionDeniedError(text);
    case 8:
      return new RateLimitError(text);
    case 12:
      return new UnsupportedError(text);
    case 16:
      return new AuthenticationError(text);
    case 10:
    case 11:
    case 14:
    case 15:
      return new UnavailableError(text);
    default:
      return new UnavailableError(text, { retryable: false });
  }
}

// ---- exporter -------------------------------------------------------------------------------

/** Options of {@link OtlpGrpcLogExporter}. */
export interface OtlpGrpcLogExporterOptions {
  /** `http://host:4317` (h2c) or `https://host:4317` (TLS). */
  endpoint: string;
  /** Bearer token configured on the input (`bearer_token`); sent as `authorization: Bearer …`. */
  bearerToken?: string | Secret;
  /** Extra gRPC metadata headers. */
  headers?: Record<string, string>;
  /** TLS settings for `https` endpoints. */
  tls?: GelfTlsOptions;
  /** Deadline of one export call. Default 30 000 ms. */
  timeoutMs?: number;
  /** Connection setup timeout. Default 10 000 ms. */
  connectTimeoutMs?: number;
}

/**
 * {@link LogExporter} for the Graylog OpenTelemetry (gRPC) input: OTLP `LogsService/Export` over
 * HTTP/2, gzip when the batch asks for it. Stored fields are `otel_*` (see API docs); the query
 * client normalises them back into log records.
 */
export class OtlpGrpcLogExporter implements LogExporter {
  readonly endpoint: string;
  readonly timeoutMs: number;
  readonly connectTimeoutMs: number;
  readonly #headers: Record<string, string>;
  readonly #secrets: string[];
  readonly #tls: GelfTlsOptions | undefined;
  #session: ClientHttp2Session | null = null;
  #closed = false;

  constructor(options: OtlpGrpcLogExporterOptions) {
    let url: URL;
    try {
      url = new URL(options.endpoint);
    } catch {
      throw new ConfigError("otlp: endpoint must be an http(s) URL");
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new ConfigError("otlp: endpoint must be an http(s) URL");
    }
    this.endpoint = url.origin;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.connectTimeoutMs = options.connectTimeoutMs ?? 10_000;
    if (!(this.timeoutMs > 0) || !(this.connectTimeoutMs > 0)) {
      throw new ConfigError("otlp: timeouts must be positive");
    }
    this.#headers = {};
    for (const [k, v] of Object.entries(options.headers ?? {})) this.#headers[k.toLowerCase()] = v;
    this.#secrets = Object.values(this.#headers).filter((v) => v.length >= 4);
    const token = Secret.from(options.bearerToken);
    if (token !== undefined) {
      this.#headers.authorization = `Bearer ${token.reveal()}`;
      this.#secrets.push(token.reveal());
    }
    this.#tls = url.protocol === "https:" ? (options.tls ?? {}) : undefined;
  }

  #getSession(): ClientHttp2Session {
    const current = this.#session;
    if (current !== null && !current.closed && !current.destroyed) return current;
    const host = new URL(this.endpoint).hostname;
    const session = connect(
      this.endpoint,
      this.#tls === undefined ? {} : tlsConnectOptions(host.replace(/^\[|\]$/g, ""), this.#tls),
    );
    session.on("error", () => {
      // surfaced through the stream; never crash the process
    });
    session.on("close", () => {
      if (this.#session === session) this.#session = null;
    });
    session.unref();
    this.#session = session;
    return session;
  }

  async export(records: LogRecord[], opts: ExportOptions): Promise<ExportResult> {
    if (this.#closed) throw new ConfigError("otlp.export: exporter is closed");
    if (records.length === 0) return { accepted: 0, rejected: 0 };
    const message = encodeExportLogsRequest(records);
    const payload = opts.gzip ? gzipSync(message) : message;
    const frame = Buffer.alloc(5 + payload.length);
    frame[0] = opts.gzip ? 1 : 0;
    frame.writeUInt32BE(payload.length, 1);
    frame.set(payload, 5);
    const response = await this.#call(frame, opts.gzip, opts.signal);
    const partial = decodeExportLogsResponse(response);
    const rejected = Math.min(records.length, Math.max(0, partial.rejectedLogRecords));
    const out: ExportResult = { accepted: records.length - rejected, rejected };
    if (rejected > 0) {
      out.error = new ValidationError(
        `otlp.export: ${rejected} records rejected${partial.errorMessage === "" ? "" : `: ${this.#redact(partial.errorMessage)}`}`,
      );
    }
    return out;
  }

  #redact(text: string): string {
    return redactText(text, this.#secrets).slice(0, 300);
  }

  #call(frame: Uint8Array, gzip: boolean, signal?: AbortSignal): Promise<Uint8Array> {
    if (signal?.aborted === true)
      return Promise.reject(new CancelledError("otlp.export: cancelled"));
    return new Promise((resolve, reject) => {
      let session: ClientHttp2Session;
      try {
        session = this.#getSession();
      } catch (err) {
        reject(new UnavailableError("otlp.export: connection failed", { cause: err }));
        return;
      }
      const headers: Record<string, string> = {
        ...this.#headers,
        [constants.HTTP2_HEADER_METHOD]: "POST",
        [constants.HTTP2_HEADER_PATH]: OTLP_LOGS_EXPORT_PATH,
        "content-type": "application/grpc",
        te: "trailers",
        "user-agent": `grow-codes-${PACKAGE_KEY}/${SDK_VERSION} (${LANGUAGE})`,
        "grpc-timeout": `${Math.max(1, Math.round(this.timeoutMs))}m`,
        "grpc-accept-encoding": "identity",
      };
      if (gzip) headers["grpc-encoding"] = "gzip";
      const stream = session.request(headers, { endStream: false });
      const chunks: Buffer[] = [];
      let grpcStatus: number | undefined;
      let grpcMessage = "";
      let httpStatus = 0;
      let settled = false;
      const finish = (err?: GraylogError, body?: Uint8Array): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        if (err !== undefined) {
          stream.close(constants.NGHTTP2_CANCEL);
          reject(err);
        } else {
          resolve(body ?? new Uint8Array());
        }
      };
      const readStatus = (h: Record<string, unknown>): void => {
        const s = h["grpc-status"];
        if (s !== undefined) grpcStatus = Number(s);
        const m = h["grpc-message"];
        if (typeof m === "string") grpcMessage = decodeURIComponent(m);
      };
      const timer = setTimeout(() => {
        finish(new TimeoutError(`otlp.export: timed out after ${this.timeoutMs} ms`));
      }, this.timeoutMs);
      const onAbort = (): void => {
        finish(new CancelledError("otlp.export: cancelled"));
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      stream.on("response", (h) => {
        httpStatus = Number(h[constants.HTTP2_HEADER_STATUS]);
        readStatus(h);
      });
      stream.on("trailers", (h: Record<string, unknown>) => {
        readStatus(h);
      });
      stream.on("data", (c: Buffer) => chunks.push(c));
      stream.on("error", (err) => {
        finish(new UnavailableError("otlp.export: network error", { cause: err }));
      });
      stream.on("close", () => {
        if (settled) return;
        if (httpStatus !== 200) {
          finish(
            new UnavailableError(
              `otlp.export: unexpected response (HTTP ${httpStatus === 0 ? "none" : httpStatus})`,
              httpStatus === 0 ? {} : { httpStatus },
            ),
          );
          return;
        }
        if (grpcStatus === undefined) {
          finish(new UnavailableError("otlp.export: response without grpc-status"));
          return;
        }
        if (grpcStatus !== 0) {
          finish(errorForGrpcStatus(grpcStatus, this.#redact(grpcMessage)));
          return;
        }
        const data = Buffer.concat(chunks);
        // A gRPC message is length-prefixed; a compressed response is not requested.
        finish(undefined, data.length >= 5 ? data.subarray(5, 5 + data.readUInt32BE(1)) : data);
      });
      stream.end(frame);
    });
  }

  async shutdown(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    const session = this.#session;
    this.#session = null;
    if (session === null || session.closed || session.destroyed) return;
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        session.destroy();
        resolve();
      }, 1000);
      session.close(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }
}
