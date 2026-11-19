import { execFileSync } from "node:child_process";
import { createSocket, type Socket as UdpSocket } from "node:dgram";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import {
  type AddressInfo,
  createServer as createNetServer,
  type Server,
  type Socket,
} from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer as createTlsServer, type Server as TlsServer } from "node:tls";
import { gunzipSync, inflateSync } from "node:zlib";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  DEFAULT_UDP_CHUNK_SIZE,
  GELF_MAX_CHUNKS,
  GelfHttpTransport,
  GelfLogExporter,
  GelfMessage,
  GelfTcpTransport,
  GelfUdpTransport,
  GraylogClient,
  Severity,
  ValidationError,
  encodeGelfUdp,
  tlsConnectOptions,
  type GelfSendResult,
  type GelfTransport,
  type LogRecord,
} from "../src/index.js";
import { type MockServer, closedPort, startServer } from "./helpers/server.js";

const msg = (text: string, fields: Record<string, unknown> = {}): GelfMessage =>
  new GelfMessage({ host: "unit", shortMessage: text, fields });

const noSleep = (): Promise<void> => Promise.resolve();

// ---- UDP ----

interface UdpSink {
  port: number;
  datagrams: Buffer[];
  close(): Promise<void>;
}

async function udpSink(): Promise<UdpSink> {
  const socket: UdpSocket = createSocket("udp4");
  const datagrams: Buffer[] = [];
  socket.on("message", (m) => datagrams.push(m));
  await new Promise<void>((r) => socket.bind(0, "127.0.0.1", r));
  return {
    port: socket.address().port,
    datagrams,
    close: () => new Promise((r) => socket.close(() => r())),
  };
}

function reassemble(datagrams: Buffer[]): Buffer {
  if (datagrams[0]?.[0] !== 0x1e) return datagrams[0] as Buffer;
  const parts = [...datagrams].sort((a, b) => (a[10] as number) - (b[10] as number));
  return Buffer.concat(parts.map((d) => d.subarray(12)));
}

async function waitFor(cond: () => boolean, ms = 3000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error("waitFor timed out");
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe("encodeGelfUdp", () => {
  const payload = Buffer.from(JSON.stringify({ short_message: "x".repeat(5000) }));

  it("single datagram per compression", () => {
    expect(gunzipSync(encodeGelfUdp(payload)[0] as Buffer).equals(payload)).toBe(true);
    expect(
      inflateSync(encodeGelfUdp(payload, { compression: "zlib" })[0] as Buffer).equals(payload),
    ).toBe(true);
    const plain = encodeGelfUdp(Buffer.from("{}"), { compression: "none" });
    expect(Buffer.from(plain[0] as Uint8Array).toString()).toBe("{}");
  });

  it("chunks with magic, id, sequence and count", () => {
    const id = Buffer.from("0123456789abcdef", "hex");
    const chunks = encodeGelfUdp(payload, { compression: "none", chunkSize: 1000, messageId: id });
    expect(chunks).toHaveLength(Math.ceil(payload.length / 988));
    chunks.forEach((c, i) => {
      expect([...c.subarray(0, 2)]).toEqual([0x1e, 0x0f]);
      expect(Buffer.from(c.subarray(2, 10)).equals(id)).toBe(true);
      expect(c[10]).toBe(i);
      expect(c[11]).toBe(chunks.length);
      expect(c.length).toBeLessThanOrEqual(1000);
    });
    expect(reassemble(chunks.map((c) => Buffer.from(c))).equals(payload)).toBe(true);
  });

  it("rejects more than 128 chunks", () => {
    const big = Buffer.alloc(GELF_MAX_CHUNKS * (64 - 12) + 1, 0x61);
    expect(() => encodeGelfUdp(big, { compression: "none", chunkSize: 64 })).toThrow(
      ValidationError,
    );
    expect(
      encodeGelfUdp(big.subarray(0, GELF_MAX_CHUNKS * 52), { compression: "none", chunkSize: 64 }),
    ).toHaveLength(128);
    expect(DEFAULT_UDP_CHUNK_SIZE).toBe(1420);
  });
});

describe("GelfUdpTransport", () => {
  let sink: UdpSink;
  beforeAll(async () => {
    sink = await udpSink();
  });
  afterAll(async () => {
    await sink.close();
  });

  it("sends gzip datagrams and chunked messages", async () => {
    sink.datagrams.length = 0;
    const t = new GelfUdpTransport({ host: "127.0.0.1", port: sink.port });
    expect(t.protocol).toBe("udp");
    expect(await t.send([msg("a"), msg("b")])).toEqual({ sent: 2, rejected: 0 });
    await waitFor(() => sink.datagrams.length === 2);
    expect(JSON.parse(gunzipSync(sink.datagrams[0] as Buffer).toString()).short_message).toBe("a");

    sink.datagrams.length = 0;
    const chunky = new GelfUdpTransport({
      host: "127.0.0.1",
      port: sink.port,
      compression: "none",
      chunkSize: 200,
    });
    const long = "y".repeat(1500);
    await chunky.send([msg(long)]);
    await waitFor(() => sink.datagrams.length >= 8);
    expect(JSON.parse(reassemble(sink.datagrams).toString()).short_message).toBe(long);
    await chunky.close();
    await t.close();
    await t.close();
    await expect(t.send([msg("x")])).rejects.toMatchObject({ code: "CONFIG" });
  });

  it("counts oversize messages as rejected and keeps sending the rest", async () => {
    sink.datagrams.length = 0;
    const t = new GelfUdpTransport({
      host: "127.0.0.1",
      port: sink.port,
      compression: "none",
      chunkSize: 64,
    });
    const result = await t.send([msg("z".repeat(10_000)), msg("ok")]);
    expect(result.sent).toBe(1);
    expect(result.rejected).toBe(1);
    expect(result.error?.code).toBe("VALIDATION");
    await t.close();
  });

  it("validates options, reports send errors and cancellation", async () => {
    expect(() => new GelfUdpTransport({ host: "" })).toThrow("host");
    expect(() => new GelfUdpTransport({ host: "h", port: 70_000 })).toThrow("port");
    // @ts-expect-error invalid compression
    expect(() => new GelfUdpTransport({ host: "h", compression: "br" })).toThrow("compression");
    expect(() => new GelfUdpTransport({ host: "h", chunkSize: 10 })).toThrow("chunkSize");
    expect(new GelfUdpTransport({ host: "::1" }).port).toBe(12201);
    const t = new GelfUdpTransport({ host: "nonexistent.invalid", port: 9 });
    await expect(t.send([msg("x")])).rejects.toMatchObject({ code: "UNAVAILABLE" });
    await t.close();
    const v6 = new GelfUdpTransport({ host: "::1", port: 9 });
    await v6.send([]).then((r: GelfSendResult) => expect(r.sent).toBe(0));
    await v6.close();
    const ac = new AbortController();
    ac.abort();
    await expect(
      new GelfUdpTransport({ host: "127.0.0.1" }).send([msg("x")], { signal: ac.signal }),
    ).rejects.toMatchObject({
      code: "CANCELLED",
    });
  });
});

// ---- TCP ----

interface TcpSink {
  port: number;
  frames: string[];
  sockets: Set<Socket>;
  server: Server | TlsServer;
  close(): Promise<void>;
}

function collect(
  server: Server | TlsServer,
  frames: string[],
  sockets: Set<Socket>,
  onSocket?: (s: Socket) => void,
  secure = false,
): void {
  server.on(secure ? "secureConnection" : "connection", (s: Socket) => {
    sockets.add(s);
    s.on("close", () => sockets.delete(s));
    s.on("error", () => undefined);
    let buf = "";
    s.on("data", (d: Buffer) => {
      buf += d.toString("utf8");
      let i: number;
      while ((i = buf.indexOf("\0")) >= 0) {
        frames.push(buf.slice(0, i));
        buf = buf.slice(i + 1);
      }
    });
    onSocket?.(s);
  });
}

async function listen(server: Server | TlsServer): Promise<number> {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return (server.address() as AddressInfo).port;
}

async function tcpSink(onSocket?: (s: Socket) => void): Promise<TcpSink> {
  const frames: string[] = [];
  const sockets = new Set<Socket>();
  const server = createNetServer();
  collect(server, frames, sockets, onSocket);
  const port = await listen(server);
  return {
    port,
    frames,
    sockets,
    server,
    close: () =>
      new Promise((r) => {
        for (const s of sockets) s.destroy();
        server.close(() => r());
      }),
  };
}

describe("GelfTcpTransport", () => {
  const sinks: TcpSink[] = [];
  afterEach(async () => {
    await Promise.all(sinks.splice(0).map((s) => s.close()));
  });

  it("writes NUL-framed JSON on one connection, serialising batches", async () => {
    const sink = await tcpSink();
    sinks.push(sink);
    const t = new GelfTcpTransport({ host: "127.0.0.1", port: sink.port });
    expect(t.protocol).toBe("tcp");
    expect(t.secure).toBe(false);
    const [a, b] = await Promise.all([t.send([msg("one"), msg("two")]), t.send([msg("three")])]);
    expect(a).toEqual({ sent: 2, rejected: 0 });
    expect(b).toEqual({ sent: 1, rejected: 0 });
    await waitFor(() => sink.frames.length === 3);
    expect(
      sink.frames.map((f) => (JSON.parse(f) as { short_message: string }).short_message),
    ).toEqual(["one", "two", "three"]);
    expect(t.connections).toBe(1);
    expect(await t.send([])).toEqual({ sent: 0, rejected: 0 });
    await t.close();
    await t.close();
    await expect(t.send([msg("x")])).rejects.toMatchObject({ code: "CONFIG" });
    expect(
      Buffer.from(GelfTcpTransport.frame([msg("q")]))
        .toString()
        .endsWith("}\0"),
    ).toBe(true);
  });

  it("reconnects after the server closes the connection", async () => {
    const sink = await tcpSink();
    sinks.push(sink);
    const t = new GelfTcpTransport({ host: "127.0.0.1", port: sink.port, sleep: noSleep });
    await t.send([msg("before")]);
    await waitFor(() => sink.frames.length === 1);
    for (const s of sink.sockets) s.destroy();
    await new Promise((r) => setTimeout(r, 50));
    await t.send([msg("after")]);
    await waitFor(() => sink.frames.length === 2);
    expect(t.connections).toBe(2);
    await t.close();
  });

  it("retries connection failures with backoff, then UNAVAILABLE", async () => {
    const port = await closedPort();
    const sleeps: number[] = [];
    const t = new GelfTcpTransport({
      host: "127.0.0.1",
      port,
      retry: { maxRetries: 2, initialBackoffMs: 10, random: () => 1 },
      sleep: (ms) => {
        sleeps.push(ms);
        return Promise.resolve();
      },
    });
    await expect(t.send([msg("x")])).rejects.toMatchObject({
      code: "UNAVAILABLE",
      message: expect.stringContaining("ECONNREFUSED") as unknown,
    });
    expect(sleeps).toEqual([10, 20]);
    await t.close();
  });

  it("connect timeout, cancellation and a cancelled backoff", async () => {
    // a TLS client against a server that never answers the handshake
    const silent = createNetServer((s) => s.on("error", () => undefined).resume());
    const port = await listen(silent);
    try {
      const t = new GelfTcpTransport({
        host: "127.0.0.1",
        port,
        tls: true,
        connectTimeoutMs: 50,
        retry: { maxRetries: 0 },
      });
      await expect(t.send([msg("x")])).rejects.toMatchObject({ code: "TIMEOUT" });
      const ac = new AbortController();
      const c = new GelfTcpTransport({
        host: "127.0.0.1",
        port,
        tls: true,
        retry: { maxRetries: 0 },
      });
      const p = c.send([msg("x")], { signal: ac.signal });
      setTimeout(() => ac.abort(), 30);
      await expect(p).rejects.toMatchObject({ code: "CANCELLED" });
      const pre = new AbortController();
      pre.abort();
      await expect(c.send([msg("x")], { signal: pre.signal })).rejects.toMatchObject({
        code: "CANCELLED",
      });
      const backoff = new GelfTcpTransport({
        host: "127.0.0.1",
        port: await closedPort(),
        sleep: () => Promise.reject(new Error("aborted")),
      });
      await expect(backoff.send([msg("x")])).rejects.toMatchObject({ code: "CANCELLED" });
      await Promise.all([t.close(), c.close(), backoff.close()]);
    } finally {
      await new Promise((r) => silent.close(() => r(undefined)));
    }
  });

  it("write timeout and write cancellation when the peer stops reading", async () => {
    const sink = await tcpSink((s) => s.pause());
    sinks.push(sink);
    const huge = msg("h".repeat(32 * 1024 * 1024));
    const t = new GelfTcpTransport({
      host: "127.0.0.1",
      port: sink.port,
      writeTimeoutMs: 100,
      retry: { maxRetries: 0 },
    });
    await expect(t.send([huge])).rejects.toMatchObject({ code: "TIMEOUT" });
    const ac = new AbortController();
    const c = new GelfTcpTransport({
      host: "127.0.0.1",
      port: sink.port,
      retry: { maxRetries: 0 },
    });
    const p = c.send([huge], { signal: ac.signal });
    setTimeout(() => ac.abort(), 100);
    await expect(p).rejects.toMatchObject({ code: "CANCELLED" });
    await Promise.all([t.close(), c.close()]);
  });

  it("a connection closed by the peer during a write is retried", async () => {
    let first = true;
    const sink = await tcpSink((s) => {
      if (first) {
        first = false;
        s.pause();
        setTimeout(() => s.destroy(), 30);
      }
    });
    sinks.push(sink);
    const t = new GelfTcpTransport({ host: "127.0.0.1", port: sink.port, sleep: noSleep });
    await t.send([msg("p".repeat(16 * 1024 * 1024))]);
    expect(t.connections).toBe(2);
    await t.close();
  });

  it("validates options", () => {
    expect(() => new GelfTcpTransport({ host: " " })).toThrow("host");
    expect(() => new GelfTcpTransport({ host: "h", port: 0 })).toThrow("port");
    expect(() => new GelfTcpTransport({ host: "h", connectTimeoutMs: 0 })).toThrow("timeouts");
    expect(new GelfTcpTransport({ host: "h" }).port).toBe(12201);
    expect(new GelfTcpTransport({ host: "h", tls: false }).secure).toBe(false);
  });
});

function hasOpenssl(): boolean {
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

describe.runIf(hasOpenssl())("GelfTcpTransport over TLS", () => {
  const dir = mkdtempSync(join(tmpdir(), "gelf-tls-"));
  const certPath = join(dir, "cert.pem");
  const keyPath = join(dir, "key.pem");
  let sink: TcpSink;

  beforeAll(async () => {
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
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-keyout",
        keyPath,
        "-out",
        certPath,
      ],
      { stdio: "ignore" },
    );
    const frames: string[] = [];
    const sockets = new Set<Socket>();
    const server = createTlsServer({ cert: readFileSync(certPath), key: readFileSync(keyPath) });
    collect(server, frames, sockets, undefined, true);
    const port = await listen(server);
    sink = {
      port,
      frames,
      sockets,
      server,
      close: () =>
        new Promise((r) => {
          for (const s of sockets) s.destroy();
          server.close(() => r());
        }),
    };
  });

  afterAll(async () => {
    await sink.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it("verifies the server with a CA file and sends frames", async () => {
    const t = new GelfTcpTransport({
      host: "localhost",
      port: sink.port,
      tls: { caCertPath: certPath, clientCertPath: certPath, clientKeyPath: keyPath },
    });
    expect(t.secure).toBe(true);
    await t.send([msg("secure")]);
    await waitFor(() => sink.frames.includes(JSON.stringify(msg("secure").toJSON())));
    await t.close();
  });

  it("rejects an unknown CA (TLS error, not retried forever) unless insecureSkipVerify", async () => {
    const strict = new GelfTcpTransport({
      host: "127.0.0.1",
      port: sink.port,
      tls: true,
      sleep: noSleep,
      retry: { maxRetries: 1 },
    });
    await expect(strict.send([msg("x")])).rejects.toMatchObject({ code: "UNAVAILABLE" });
    const lax = new GelfTcpTransport({
      host: "127.0.0.1",
      port: sink.port,
      tls: { insecureSkipVerify: true },
    });
    await lax.send([msg("lax")]);
    await Promise.all([strict.close(), lax.close()]);
  });

  it("tlsConnectOptions", () => {
    expect(tlsConnectOptions("127.0.0.1", {})).toEqual({ rejectUnauthorized: true });
    expect(tlsConnectOptions("::1", {}).servername).toBeUndefined();
    expect(tlsConnectOptions("graylog", { caCertPem: "PEM", insecureSkipVerify: true })).toEqual({
      rejectUnauthorized: false,
      ca: ["PEM"],
      servername: "graylog",
    });
    expect(tlsConnectOptions("graylog", { servername: "other" }).servername).toBe("other");
  });
});

// ---- HTTP ----

describe("GelfHttpTransport", () => {
  const servers: MockServer[] = [];
  afterEach(async () => {
    await Promise.all(servers.splice(0).map((s) => s.close()));
  });

  async function gelfServer(
    responses: { status: number }[] = [{ status: 202 }],
  ): Promise<MockServer & { bodies: Buffer[] }> {
    const bodies: Buffer[] = [];
    const s = await startServer(
      (_req, i) => responses[Math.min(i, responses.length - 1)] ?? { status: 202 },
    );
    servers.push(s);
    return Object.assign(s, { bodies });
  }

  it("bulk gzip: newline-terminated messages, content headers, custom headers", async () => {
    const raw: Buffer[] = [];
    const s = await startServer(() => ({ status: 202 }));
    servers.push(s);
    // capture raw bytes through a second server for gzip
    const { createServer } = await import("node:http");
    const gz = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        raw.push(Buffer.concat(chunks));
        res.writeHead(202).end();
      });
    });
    await new Promise<void>((r) => gz.listen(0, "127.0.0.1", r));
    const url = `http://127.0.0.1:${(gz.address() as AddressInfo).port}/gelf`;
    try {
      const t = new GelfHttpTransport({ url, headers: { "X-Gelf-Auth": "input-secret" } });
      expect(t.protocol).toBe("http");
      expect(await t.send([msg("a"), msg("b")])).toEqual({ sent: 2, rejected: 0 });
      const text = gunzipSync(raw[0] as Buffer).toString("utf8");
      expect(text).toBe(`${msg("a").toString()}\n${msg("b").toString()}\n`);
      await t.close();
    } finally {
      await new Promise((r) => gz.close(() => r(undefined)));
    }
  });

  it("plain single requests carry content-type and auth header", async () => {
    const s = await gelfServer();
    const t = new GelfHttpTransport({
      url: `${s.url}/gelf`,
      gzip: false,
      bulk: false,
      headers: { authorization: "Token abcd" },
    });
    expect(await t.send([msg("a"), msg("b"), msg("c")])).toEqual({ sent: 3, rejected: 0 });
    expect(s.requests).toHaveLength(3);
    expect(s.requests[0]?.headers["content-type"]).toBe("application/json");
    expect(s.requests[0]?.headers["content-encoding"]).toBeUndefined();
    expect(s.requests[0]?.headers.authorization).toBe("Token abcd");
    expect(s.requests[0]?.body).toBe(`${msg("a").toString()}\n`);
    expect(s.requests[0]?.url).toBe("/gelf");
    expect(await t.send([])).toEqual({ sent: 0, rejected: 0 });
    // per-call gzip override
    await t.send([msg("z")], { gzip: true });
    expect(s.requests[3]?.headers["content-encoding"]).toBe("gzip");
  });

  it("errors: 400 → VALIDATION, 429 retried, 503 not retried for POST", async () => {
    const s = await gelfServer([
      { status: 429 },
      { status: 202 },
      { status: 400 },
      { status: 503 },
    ]);
    const t = new GelfHttpTransport({
      url: `${s.url}/gelf`,
      config: {
        retry: (await import("../src/index.js")).RetryPolicy.from({
          maxRetries: 2,
          initialBackoffMs: 1,
        }),
      },
    });
    await t.send([msg("a")]);
    expect(s.requests).toHaveLength(2);
    await expect(t.send([msg("b")])).rejects.toMatchObject({ code: "VALIDATION", httpStatus: 400 });
    await expect(t.send([msg("c")])).rejects.toMatchObject({
      code: "UNAVAILABLE",
      httpStatus: 503,
    });
    expect(s.requests).toHaveLength(4);
    const ac = new AbortController();
    ac.abort();
    await expect(t.send([msg("d")], { signal: ac.signal })).rejects.toMatchObject({
      code: "CANCELLED",
    });
    await t.close();
  });

  it("validates the URL", () => {
    expect(() => new GelfHttpTransport({ url: "nope" })).toThrow("url");
    expect(() => new GelfHttpTransport({ url: "ftp://x/gelf" })).toThrow("url");
  });
});

// ---- exporter + client wiring ----

function is<T>(value: unknown, ctor: abstract new (...args: never[]) => T): T {
  if (!(value instanceof ctor)) throw new Error(`expected ${ctor.name}`);
  return value;
}

class FakeTransport implements GelfTransport {
  readonly protocol = "tcp" as const;
  sent: GelfMessage[][] = [];
  closed = false;
  result: GelfSendResult | undefined;
  send(messages: readonly GelfMessage[]): Promise<GelfSendResult> {
    this.sent.push([...messages]);
    return Promise.resolve(this.result ?? { sent: messages.length, rejected: 0 });
  }
  close(): Promise<void> {
    this.closed = true;
    return Promise.resolve();
  }
}

const rec = (body: string): LogRecord => ({
  timestamp: new Date(0),
  severity: Severity.Error,
  severityText: "ERROR",
  body,
  attributes: {},
  resource: {},
});

describe("GelfLogExporter", () => {
  it("converts records, passes signal/gzip and reports rejections", async () => {
    const t = new FakeTransport();
    const e = new GelfLogExporter(t, { host: "exp" });
    expect(
      await e.export([rec("a")], { gzip: true, signal: new AbortController().signal }),
    ).toEqual({ accepted: 1, rejected: 0 });
    expect(t.sent[0]?.[0]?.toJSON()).toMatchObject({ host: "exp", short_message: "a", level: 3 });
    const error = new ValidationError("too big");
    t.result = { sent: 0, rejected: 1, error };
    expect(await e.export([rec("b")], { gzip: false })).toEqual({
      accepted: 0,
      rejected: 1,
      error,
    });
    await e.shutdown();
    expect(t.closed).toBe(true);
    expect(new GelfLogExporter(t).transport).toBe(t);
  });
});

describe("GraylogClient logging wiring", () => {
  it("gelfTransport builds each protocol from the config", async () => {
    const client = new GraylogClient({ url: "http://gl:9000", gelfTls: true, gelfPort: 1234 });
    const udp = is(
      client.gelfTransport("udp", { compression: "zlib", chunkSize: 500 }),
      GelfUdpTransport,
    );
    expect([udp.host, udp.port, udp.compression, udp.chunkSize]).toEqual(["gl", 1234, "zlib", 500]);
    const tcp = is(client.gelfTransport(), GelfTcpTransport);
    expect([tcp.host, tcp.port, tcp.secure]).toEqual(["gl", 1234, true]);
    const http = is(
      client.gelfTransport("http", { bulk: false, headers: { a: "b" } }),
      GelfHttpTransport,
    );
    expect(http.url).toBe("https://gl:1234/gelf");
    expect(http.bulk).toBe(false);
    // @ts-expect-error invalid protocol
    expect(() => client.gelfTransport("smtp")).toThrow("protocol");
    expect(is(new GraylogClient().gelfTransport("udp"), GelfUdpTransport).compression).toBe("gzip");
    await Promise.all([udp.close(), tcp.close(), http.close(), client.close()]);
  });

  it("logClient sends through a GELF transport and close() flushes it", async () => {
    const sink = await tcpSink();
    try {
      const client = new GraylogClient({ gelfHost: "127.0.0.1", gelfPort: sink.port });
      const logs = client.logClient({
        host: "svc-host",
        batch: { flushIntervalMs: 60_000 },
        resource: { "service.name": "svc" },
      });
      logs.logger("unit").warn("queued", { password: "hunter2" });
      await client.close();
      await client.close();
      expect(sink.frames).toHaveLength(1);
      const frame = JSON.parse(sink.frames[0] as string) as Record<string, unknown>;
      expect(frame).toMatchObject({
        host: "svc-host",
        short_message: "queued",
        level: 4,
        "_service.name": "svc",
      });
      expect(frame._password).toBe("[REDACTED]");
    } finally {
      await sink.close();
    }
  });

  it("logClient with a custom transport, udp/http/otlp exporters", async () => {
    const client = new GraylogClient();
    const fake = new FakeTransport();
    const logs = client.logClient({ transport: fake, batch: { flushIntervalMs: 60_000 } });
    logs.send({ message: "x" });
    await logs.flush();
    expect(fake.sent).toHaveLength(1);
    client.logClient({ protocol: "udp" });
    client.logClient({ protocol: "http", bulk: true, headers: { a: "b" } });
    client.logClient({ protocol: "otlp", bearerToken: "otlp-token", headers: { x: "y" } });
    client.logClient({ protocol: "otlp" });
    await client.close();
    expect(fake.closed).toBe(true);
  });
});
