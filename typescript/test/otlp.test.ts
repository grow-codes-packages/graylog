import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import {
  createSecureServer,
  createServer,
  type Http2Server,
  type Http2SecureServer,
  type IncomingHttpHeaders,
  type ServerHttp2Stream,
} from "node:http2";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import {
  OTLP_LOGS_EXPORT_PATH,
  OtlpGrpcLogExporter,
  ProtoWriter,
  Severity,
  decodeExportLogsResponse,
  encodeExportLogsRequest,
  errorForGrpcStatus,
  type LogRecord,
} from "../src/index.js";
import { closedPort } from "./helpers/server.js";

// ---- tiny protobuf decoder for assertions ----

type Field = { field: number; wire: number; value: bigint | Buffer };

function varint(buf: Buffer, pos: number): [bigint, number] {
  let r = 0n;
  let shift = 0n;
  for (;;) {
    const b = buf[pos++] as number;
    r |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) return [r, pos];
    shift += 7n;
  }
}

function decode(buf: Buffer): Field[] {
  const out: Field[] = [];
  let pos = 0;
  while (pos < buf.length) {
    const [tag, p] = varint(buf, pos);
    pos = p;
    const field = Number(tag >> 3n);
    const wire = Number(tag & 7n);
    if (wire === 0) {
      const [v, p2] = varint(buf, pos);
      pos = p2;
      out.push({ field, wire, value: v });
    } else if (wire === 1) {
      out.push({ field, wire, value: buf.subarray(pos, pos + 8) });
      pos += 8;
    } else if (wire === 5) {
      out.push({ field, wire, value: buf.subarray(pos, pos + 4) });
      pos += 4;
    } else {
      const [len, p2] = varint(buf, pos);
      out.push({ field, wire, value: buf.subarray(p2, p2 + Number(len)) });
      pos = p2 + Number(len);
    }
  }
  return out;
}

const sub = (fs: Field[], n: number): Buffer[] =>
  fs.filter((f) => f.field === n).map((f) => f.value as Buffer);
const str = (b: Buffer | undefined): string => (b ?? Buffer.alloc(0)).toString("utf8");

function anyValue(b: Buffer): unknown {
  const [f] = decode(b);
  if (f === undefined) return undefined;
  switch (f.field) {
    case 1:
      return str(f.value as Buffer);
    case 2:
      return f.value === 1n;
    case 3:
      return BigInt.asIntN(64, f.value as bigint);
    case 4:
      return (f.value as Buffer).readDoubleLE();
    case 5:
      return sub(decode(f.value as Buffer), 1).map(anyValue);
    case 6:
      return Object.fromEntries(sub(decode(f.value as Buffer), 1).map(kv));
    default:
      return f.value;
  }
}

function kv(b: Buffer): [string, unknown] {
  const fs = decode(b);
  return [str(sub(fs, 1)[0]), anyValue(sub(fs, 2)[0] as Buffer)];
}

function rec(overrides: Partial<LogRecord> = {}): LogRecord {
  return {
    timestamp: new Date("2026-11-18T20:00:00.123Z"),
    severity: Severity.Warn,
    severityText: "WARN",
    body: "hello",
    attributes: {},
    resource: { "service.name": "a" },
    ...overrides,
  };
}

describe("OTLP protobuf encoding", () => {
  it("groups by resource and encodes every field", () => {
    const records = [
      rec({
        attributes: { s: "x", b: true, i: 7, d: 1.5, arr: [1, "two"], obj: { k: "v" }, neg: -3 },
        traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
        spanId: "00f067aa0ba902b7",
        traceFlags: 1,
        observedTimestamp: new Date("2026-11-18T20:00:01.000Z"),
      }),
      rec({ body: "second" }),
      rec({ body: "other", resource: { "service.name": "b" } }),
    ];
    const req = decode(Buffer.from(encodeExportLogsRequest(records)));
    const resourceLogs = sub(req, 1);
    expect(resourceLogs).toHaveLength(2);
    const rl = decode(resourceLogs[0] as Buffer);
    const resource = decode(sub(rl, 1)[0] as Buffer);
    expect(Object.fromEntries(sub(resource, 1).map(kv))).toEqual({ "service.name": "a" });
    const sl = decode(sub(rl, 2)[0] as Buffer);
    const scope = decode(sub(sl, 1)[0] as Buffer);
    expect(str(sub(scope, 1)[0])).toBe("grow-codes-graylog");
    const logRecords = sub(sl, 2).map((b) => decode(b));
    expect(logRecords).toHaveLength(2);
    const lr = logRecords[0] as Field[];
    const get = (n: number): Field | undefined => lr.find((f) => f.field === n);
    expect((get(1)?.value as Buffer).readBigUInt64LE()).toBe(1795032000123000000n);
    expect((get(11)?.value as Buffer).readBigUInt64LE()).toBe(1795032001000000000n);
    expect(get(2)?.value).toBe(13n);
    expect(str(get(3)?.value as Buffer)).toBe("WARN");
    expect(anyValue(get(5)?.value as Buffer)).toBe("hello");
    expect(Object.fromEntries(sub(lr, 6).map(kv))).toEqual({
      s: "x",
      b: true,
      i: 7n,
      d: 1.5,
      arr: [1n, "two"],
      obj: { k: "v" },
      neg: -3n,
    });
    expect((get(8)?.value as Buffer).readUInt32LE()).toBe(1);
    expect((get(9)?.value as Buffer).toString("hex")).toBe("4bf92f3577b34da6a3ce929d0e0e4736");
    expect((get(10)?.value as Buffer).toString("hex")).toBe("00f067aa0ba902b7");
    const second = logRecords[1] as Field[];
    expect(second.some((f) => f.field === 9)).toBe(false);
    expect(encodeExportLogsRequest([])).toHaveLength(0);
  });

  it("ProtoWriter primitives", () => {
    const w = new ProtoWriter().varint(1, false).varint(2, 300).fixed32(3, 7).string(4, "é");
    expect(Buffer.from(w.finish()).toString("hex")).toBe(
      "0800" + "10ac02" + "1d07000000" + "2202c3a9",
    );
  });

  it("decodes partial success, tolerates garbage", () => {
    const body = new ProtoWriter()
      .message(1, (p) => p.varint(1, 2).string(2, "bad records").fixed32(3, 1))
      .fixed64(2, 1n)
      .finish();
    expect(decodeExportLogsResponse(body)).toEqual({
      rejectedLogRecords: 2,
      errorMessage: "bad records",
    });
    expect(decodeExportLogsResponse(new Uint8Array())).toEqual({
      rejectedLogRecords: 0,
      errorMessage: "",
    });
    expect(decodeExportLogsResponse(Uint8Array.of(0x0a, 0x05, 0x01))).toEqual({
      rejectedLogRecords: 0,
      errorMessage: "",
    });
    expect(decodeExportLogsResponse(Uint8Array.of(0x0b))).toEqual({
      rejectedLogRecords: 0,
      errorMessage: "",
    });
    expect(decodeExportLogsResponse(Uint8Array.of(0x08, 0x80))).toEqual({
      rejectedLogRecords: 0,
      errorMessage: "",
    });
  });

  it("maps gRPC status codes", () => {
    const table: [number, string, boolean][] = [
      [1, "CANCELLED", false],
      [3, "VALIDATION", false],
      [9, "VALIDATION", false],
      [4, "TIMEOUT", true],
      [5, "NOT_FOUND", false],
      [6, "CONFLICT", false],
      [7, "PERMISSION_DENIED", false],
      [8, "RATE_LIMITED", true],
      [12, "UNSUPPORTED", false],
      [16, "AUTHENTICATION", false],
      [10, "UNAVAILABLE", true],
      [11, "UNAVAILABLE", true],
      [14, "UNAVAILABLE", true],
      [15, "UNAVAILABLE", true],
      [13, "UNAVAILABLE", false],
      [2, "UNAVAILABLE", false],
    ];
    for (const [status, code, retryable] of table) {
      expect(errorForGrpcStatus(status, "m"), String(status)).toMatchObject({ code, retryable });
    }
    expect(errorForGrpcStatus(14, "").message).toBe("otlp.export: gRPC status 14 (gRPC 14)");
  });
});

// ---- exporter against a local HTTP/2 server ----

type Handler = (stream: ServerHttp2Stream, headers: IncomingHttpHeaders, body: Buffer) => void;

interface H2 {
  url: string;
  requests: { headers: IncomingHttpHeaders; body: Buffer }[];
  close(): Promise<void>;
}

async function h2(handler: Handler, secure?: { cert: Buffer; key: Buffer }): Promise<H2> {
  const requests: H2["requests"] = [];
  const server: Http2Server | Http2SecureServer = secure
    ? createSecureServer(secure)
    : createServer();
  const sessions = new Set<{ destroy(): void }>();
  server.on("session", (s) => sessions.add(s));
  server.on("stream", (stream, headers) => {
    const chunks: Buffer[] = [];
    stream.on("data", (c: Buffer) => chunks.push(c));
    stream.on("end", () => {
      const body = Buffer.concat(chunks);
      requests.push({ headers, body });
      handler(stream, headers, body);
    });
    stream.on("error", () => undefined);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `${secure ? "https" : "http"}://127.0.0.1:${port}`,
    requests,
    close: () =>
      new Promise((r) => {
        for (const s of sessions) s.destroy();
        server.close(() => r());
      }),
  };
}

function grpcOk(stream: ServerHttp2Stream, message: Uint8Array = new Uint8Array()): void {
  stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
  stream.on("wantTrailers", () => stream.sendTrailers({ "grpc-status": "0" }));
  const frame = Buffer.alloc(5 + message.length);
  frame.writeUInt32BE(message.length, 1);
  frame.set(message, 5);
  stream.end(frame);
}

function unframe(body: Buffer, gzip: boolean): Buffer {
  expect(body[0]).toBe(gzip ? 1 : 0);
  const payload = body.subarray(5, 5 + body.readUInt32BE(1));
  return gzip ? gunzipSync(payload) : payload;
}

describe("OtlpGrpcLogExporter", () => {
  const servers: H2[] = [];
  afterEach(async () => {
    await Promise.all(servers.splice(0).map((s) => s.close()));
  });
  async function server(handler: Handler, secure?: { cert: Buffer; key: Buffer }): Promise<H2> {
    const s = await h2(handler, secure);
    servers.push(s);
    return s;
  }

  it("exports with gRPC framing, gzip, bearer token and metadata", async () => {
    const s = await server((stream) => grpcOk(stream));
    const e = new OtlpGrpcLogExporter({
      endpoint: `${s.url}/ignored`,
      bearerToken: "otlp-secret",
      headers: { "X-Tenant": "t1" },
    });
    expect(e.endpoint).toBe(s.url);
    expect(await e.export([rec(), rec()], { gzip: true })).toEqual({ accepted: 2, rejected: 0 });
    const req = s.requests[0];
    expect(req?.headers[":path"]).toBe(OTLP_LOGS_EXPORT_PATH);
    expect(req?.headers["content-type"]).toBe("application/grpc");
    expect(req?.headers["grpc-encoding"]).toBe("gzip");
    expect(req?.headers.te).toBe("trailers");
    expect(req?.headers.authorization).toBe("Bearer otlp-secret");
    expect(req?.headers["x-tenant"]).toBe("t1");
    expect(req?.headers["user-agent"]).toMatch(/^grow-codes-graylog\//);
    const message = decode(unframe(req?.body as Buffer, true));
    expect(sub(message, 1)).toHaveLength(1);
    // plain frame, same session
    expect(await e.export([rec()], { gzip: false })).toEqual({ accepted: 1, rejected: 0 });
    expect(s.requests[1]?.headers["grpc-encoding"]).toBeUndefined();
    unframe(s.requests[1]?.body as Buffer, false);
    expect(await e.export([], { gzip: false })).toEqual({ accepted: 0, rejected: 0 });
    await e.shutdown();
    await e.shutdown();
    await expect(e.export([rec()], { gzip: false })).rejects.toMatchObject({ code: "CONFIG" });
  });

  it("reports partial success", async () => {
    const response = new ProtoWriter()
      .message(1, (p) => p.varint(1, 1).string(2, "dropped otlp-secret"))
      .finish();
    const s = await server((stream) => grpcOk(stream, response));
    const e = new OtlpGrpcLogExporter({ endpoint: s.url, bearerToken: "otlp-secret" });
    const result = await e.export([rec(), rec()], { gzip: false });
    expect(result.accepted).toBe(1);
    expect(result.rejected).toBe(1);
    expect(result.error?.code).toBe("VALIDATION");
    expect(result.error?.message).toContain("dropped");
    expect(result.error?.message).not.toContain("otlp-secret");
    const bare = await server((stream) =>
      grpcOk(stream, new ProtoWriter().message(1, (p) => p.varint(1, 9)).finish()),
    );
    const r2 = await new OtlpGrpcLogExporter({ endpoint: bare.url }).export([rec()], {
      gzip: false,
    });
    expect(r2).toMatchObject({ accepted: 0, rejected: 1 });
    expect(r2.error?.message).toBe("otlp.export: 1 records rejected");
    await e.shutdown();
  });

  it("maps gRPC errors from trailers and trailers-only responses", async () => {
    const s = await server((stream, headers) => {
      if (headers["x-case"] === "trailers") {
        stream.respond(
          { ":status": 200, "content-type": "application/grpc" },
          { waitForTrailers: true },
        );
        stream.on("wantTrailers", () =>
          stream.sendTrailers({
            "grpc-status": "16",
            "grpc-message": encodeURIComponent("bad token otlp-secret"),
          }),
        );
        stream.end();
      } else if (headers["x-case"] === "only") {
        stream.respond(
          { ":status": 200, "content-type": "application/grpc", "grpc-status": "14" },
          { endStream: true },
        );
      } else if (headers["x-case"] === "http500") {
        stream.respond({ ":status": 500 }, { endStream: true });
      } else {
        stream.respond({ ":status": 200, "content-type": "application/grpc" }, { endStream: true });
      }
    });
    const make = (c: string): OtlpGrpcLogExporter =>
      new OtlpGrpcLogExporter({
        endpoint: s.url,
        bearerToken: "otlp-secret",
        headers: { "x-case": c },
      });
    const auth = (await make("trailers")
      .export([rec()], { gzip: false })
      .catch((e: unknown) => e)) as Error;
    expect(auth).toMatchObject({ code: "AUTHENTICATION" });
    expect(auth.message).toContain("bad token");
    expect(auth.message).not.toContain("otlp-secret");
    await expect(make("only").export([rec()], { gzip: false })).rejects.toMatchObject({
      code: "UNAVAILABLE",
      retryable: true,
    });
    await expect(make("http500").export([rec()], { gzip: false })).rejects.toMatchObject({
      code: "UNAVAILABLE",
      httpStatus: 500,
    });
    await expect(make("none").export([rec()], { gzip: false })).rejects.toThrow(
      "without grpc-status",
    );
  });

  it("times out, cancels and reports network errors", async () => {
    const s = await server(() => undefined); // never answers
    const slow = new OtlpGrpcLogExporter({ endpoint: s.url, timeoutMs: 50 });
    await expect(slow.export([rec()], { gzip: false })).rejects.toMatchObject({ code: "TIMEOUT" });
    const ac = new AbortController();
    const p = slow.export([rec()], { gzip: false, signal: ac.signal });
    setTimeout(() => ac.abort(), 10);
    // the 50 ms timeout may win on a slow machine; both are acceptable outcomes of an abandoned call
    await expect(p).rejects.toMatchObject({
      code: expect.stringMatching(/CANCELLED|TIMEOUT/) as unknown,
    });
    const pre = new AbortController();
    pre.abort();
    await expect(slow.export([rec()], { gzip: false, signal: pre.signal })).rejects.toMatchObject({
      code: "CANCELLED",
    });
    await slow.shutdown();

    const down = new OtlpGrpcLogExporter({ endpoint: `http://127.0.0.1:${await closedPort()}` });
    await expect(down.export([rec()], { gzip: false })).rejects.toMatchObject({
      code: "UNAVAILABLE",
    });
    await down.shutdown();
  });

  it("reconnects after the session closes and shuts down an open session", async () => {
    const s = await server((stream) => grpcOk(stream));
    const e = new OtlpGrpcLogExporter({ endpoint: s.url });
    await e.export([rec()], { gzip: false });
    await s.close();
    servers.splice(servers.indexOf(s), 1);
    await new Promise((r) => setTimeout(r, 50));
    await expect(e.export([rec()], { gzip: false })).rejects.toMatchObject({ code: "UNAVAILABLE" });
    await e.shutdown();
  });

  it("validates options", () => {
    expect(() => new OtlpGrpcLogExporter({ endpoint: "nope" })).toThrow("endpoint");
    expect(() => new OtlpGrpcLogExporter({ endpoint: "grpc://x:1" })).toThrow("endpoint");
    expect(() => new OtlpGrpcLogExporter({ endpoint: "http://x:1", timeoutMs: 0 })).toThrow(
      "timeouts",
    );
  });

  function hasOpenssl(): boolean {
    try {
      execFileSync("openssl", ["version"], { stdio: "ignore" });
      return true;
    } catch {
      return false;
    }
  }

  it.runIf(hasOpenssl())("exports over TLS (https endpoint)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "otlp-tls-"));
    try {
      const certPath = join(dir, "cert.pem");
      const keyPath = join(dir, "key.pem");
      execFileSync(
        "openssl",
        [
          "req",
          "-x509",
          "-newkey",
          "rsa:2048",
          "-nodes",
          "-days",
          "1",
          "-subj",
          "/CN=localhost",
          "-addext",
          "subjectAltName=IP:127.0.0.1",
          "-keyout",
          keyPath,
          "-out",
          certPath,
        ],
        { stdio: "ignore" },
      );
      const s = await server((stream) => grpcOk(stream), {
        cert: readFileSync(certPath),
        key: readFileSync(keyPath),
      });
      const e = new OtlpGrpcLogExporter({ endpoint: s.url, tls: { caCertPath: certPath } });
      expect(await e.export([rec()], { gzip: true })).toEqual({ accepted: 1, rejected: 0 });
      await e.shutdown();
      const strict = new OtlpGrpcLogExporter({ endpoint: s.url });
      await expect(strict.export([rec()], { gzip: false })).rejects.toMatchObject({
        code: "UNAVAILABLE",
      });
      await strict.shutdown();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
