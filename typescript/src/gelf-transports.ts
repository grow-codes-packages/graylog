// Service-owned: GELF transports (UDP chunked, TCP null-framed with TLS and reconnect, HTTP bulk)
// and the LogExporter that plugs them into the shared BatchingLogClient.

import { randomBytes } from "node:crypto";
import { createSocket, type Socket as UdpSocket } from "node:dgram";
import { readFileSync } from "node:fs";
import { isIPv6, connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect, type ConnectionOptions } from "node:tls";
import { deflateSync, gzipSync } from "node:zlib";
import {
  CancelledError,
  ConfigError,
  type CommonConfig,
  type GraylogError,
  HttpTransport,
  RetryPolicy,
  type RetryPolicyOptions,
  type TlsOptions,
  type TransportOptions,
  UnavailableError,
  TimeoutError,
  ValidationError,
  sleep as abortableSleep,
} from "./core/index.js";
import type { GelfProtocol } from "./config.js";
import { GelfMessage, type FromLogRecordOptions } from "./gelf.js";
import type { ExportOptions, ExportResult, LogExporter, LogRecord } from "./logging/index.js";

/** Per-call options of {@link GelfTransport.send}. */
export interface GelfSendOptions {
  /** Cancels the send (`CancelledError`). */
  signal?: AbortSignal;
  /** HTTP only: gzip the body (default: the transport's `gzip` option). */
  gzip?: boolean;
}

/** Outcome of {@link GelfTransport.send}. */
export interface GelfSendResult {
  /** Messages handed to the network. */
  sent: number;
  /** Messages rejected client side (e.g. too large for UDP). */
  rejected: number;
  /** Why messages were rejected. */
  error?: GraylogError;
}

/** Sends GELF messages to a Graylog input. */
export interface GelfTransport {
  /** `udp`, `tcp` or `http`. */
  readonly protocol: GelfProtocol;
  /**
   * Sends the messages. Network failures throw (`UnavailableError`, `TimeoutError`,
   * `CancelledError`); client-side rejections are counted in the result.
   */
  send(messages: readonly GelfMessage[], options?: GelfSendOptions): Promise<GelfSendResult>;
  /** Releases sockets; idempotent. Later sends throw `ConfigError`. */
  close(): Promise<void>;
}

function checkPort(port: number, op: string): void {
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new ConfigError(`${op}: port must be an integer 1..65535`);
  }
}

function checkHost(host: string, op: string): void {
  if (typeof host !== "string" || host.trim() === "") {
    throw new ConfigError(`${op}: host must not be blank`);
  }
}

function errorCode(err: unknown): string | undefined {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === "string" ? code : undefined;
}

function networkError(op: string, err: unknown): UnavailableError {
  const code = errorCode(err);
  return new UnavailableError(`${op}: network error${code === undefined ? "" : ` (${code})`}`, {
    cause: err,
  });
}

// ---- UDP ------------------------------------------------------------------------------------

/** Payload compression of {@link GelfUdpTransport}. */
export type GelfCompression = "gzip" | "zlib" | "none";

/** GELF chunk magic bytes. */
export const GELF_CHUNK_MAGIC = Uint8Array.of(0x1e, 0x0f);
/** Bytes of a chunk header: magic (2) + message id (8) + sequence (1) + count (1). */
export const GELF_CHUNK_HEADER_SIZE = 12;
/** Most chunks Graylog reassembles for one message. */
export const GELF_MAX_CHUNKS = 128;
/** Default chunk size (bytes per datagram, header included), safe for a 1500-byte MTU. */
export const DEFAULT_UDP_CHUNK_SIZE = 1420;

/** Options of {@link GelfUdpTransport}. */
export interface GelfUdpTransportOptions {
  host: string;
  /** Default 12201. */
  port?: number;
  /** Default `gzip`. */
  compression?: GelfCompression;
  /** Bytes per datagram including the 12-byte chunk header (64..65507). Default 1420. */
  chunkSize?: number;
}

/**
 * Compresses (optional) and splits a GELF payload into datagrams: one datagram when it fits
 * `chunkSize`, else chunks `0x1e 0x0f | id(8) | seq | count | data`. Throws
 * {@link ValidationError} when more than 128 chunks would be needed.
 */
export function encodeGelfUdp(
  payload: Uint8Array,
  options: { compression?: GelfCompression; chunkSize?: number; messageId?: Uint8Array } = {},
): Uint8Array[] {
  const compression = options.compression ?? "gzip";
  const chunkSize = options.chunkSize ?? DEFAULT_UDP_CHUNK_SIZE;
  const data =
    compression === "gzip"
      ? gzipSync(payload)
      : compression === "zlib"
        ? deflateSync(payload)
        : Buffer.from(payload);
  if (data.length <= chunkSize) return [data];
  const per = chunkSize - GELF_CHUNK_HEADER_SIZE;
  const count = Math.ceil(data.length / per);
  if (count > GELF_MAX_CHUNKS) {
    throw new ValidationError(
      `gelf.udp: message needs ${count} chunks (max ${GELF_MAX_CHUNKS}); use TCP or HTTP for large messages`,
    );
  }
  const id = options.messageId ?? randomBytes(8);
  const chunks: Uint8Array[] = [];
  for (let seq = 0; seq < count; seq++) {
    const part = data.subarray(seq * per, (seq + 1) * per);
    const chunk = Buffer.alloc(GELF_CHUNK_HEADER_SIZE + part.length);
    chunk.set(GELF_CHUNK_MAGIC, 0);
    chunk.set(id.subarray(0, 8), 2);
    chunk[10] = seq;
    chunk[11] = count;
    chunk.set(part, GELF_CHUNK_HEADER_SIZE);
    chunks.push(chunk);
  }
  return chunks;
}

/** GELF over UDP: fire-and-forget datagrams, compressed, chunked up to 128 chunks. */
export class GelfUdpTransport implements GelfTransport {
  readonly protocol = "udp" as const;
  readonly host: string;
  readonly port: number;
  readonly compression: GelfCompression;
  readonly chunkSize: number;
  #socket: UdpSocket | null = null;
  #closed = false;

  constructor(options: GelfUdpTransportOptions) {
    checkHost(options.host, "gelf.udp");
    this.host = options.host;
    this.port = options.port ?? 12201;
    checkPort(this.port, "gelf.udp");
    this.compression = options.compression ?? "gzip";
    if (!["gzip", "zlib", "none"].includes(this.compression)) {
      throw new ConfigError("gelf.udp: compression must be gzip, zlib or none");
    }
    this.chunkSize = options.chunkSize ?? DEFAULT_UDP_CHUNK_SIZE;
    if (!Number.isInteger(this.chunkSize) || this.chunkSize < 64 || this.chunkSize > 65_507) {
      throw new ConfigError("gelf.udp: chunkSize must be an integer 64..65507");
    }
  }

  #getSocket(): UdpSocket {
    if (this.#socket === null) {
      const socket = createSocket(isIPv6(this.host) ? "udp6" : "udp4");
      socket.on("error", () => {
        // errors surface through the send callback; never crash the process
      });
      socket.unref();
      this.#socket = socket;
    }
    return this.#socket;
  }

  async send(
    messages: readonly GelfMessage[],
    options: GelfSendOptions = {},
  ): Promise<GelfSendResult> {
    if (this.#closed) throw new ConfigError("gelf.udp: transport is closed");
    let sent = 0;
    let rejected = 0;
    let error: GraylogError | undefined;
    for (const message of messages) {
      if (options.signal?.aborted === true) throw new CancelledError("gelf.udp: cancelled");
      let datagrams: Uint8Array[];
      try {
        datagrams = encodeGelfUdp(message.encode(), {
          compression: this.compression,
          chunkSize: this.chunkSize,
        });
      } catch (err) {
        rejected++;
        error = err as GraylogError;
        continue;
      }
      for (const datagram of datagrams) await this.#sendDatagram(datagram);
      sent++;
    }
    return error === undefined ? { sent, rejected } : { sent, rejected, error };
  }

  #sendDatagram(datagram: Uint8Array): Promise<void> {
    return new Promise((resolve, reject) => {
      this.#getSocket().send(datagram, this.port, this.host, (err) => {
        if (err) reject(networkError("gelf.udp", err));
        else resolve();
      });
    });
  }

  close(): Promise<void> {
    if (this.#closed) return Promise.resolve();
    this.#closed = true;
    const socket = this.#socket;
    this.#socket = null;
    if (socket === null) return Promise.resolve();
    return new Promise((resolve) => {
      socket.close(() => {
        resolve();
      });
    });
  }
}

// ---- TCP ------------------------------------------------------------------------------------

/** TLS settings of {@link GelfTcpTransport} (same fields as the client `tls` option plus SNI). */
export interface GelfTlsOptions extends TlsOptions {
  /** SNI / certificate host name. Default: `host` (unless it is an IP address). */
  servername?: string;
}

/** Options of {@link GelfTcpTransport}. */
export interface GelfTcpTransportOptions {
  host: string;
  /** Default 12201. */
  port?: number;
  /** `true` or TLS settings to connect with TLS. Default plain TCP. */
  tls?: boolean | GelfTlsOptions;
  /** Connection setup timeout. Default 10 000 ms. */
  connectTimeoutMs?: number;
  /** Deadline for writing one batch (connect + write). Default 30 000 ms. */
  writeTimeoutMs?: number;
  /** Reconnect policy: attempts after a failed connect/write. Default `maxRetries` 3. */
  retry?: RetryPolicy | RetryPolicyOptions;
  /** Test seam: backoff sleep. */
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
}

function pem(path: string | undefined): string | undefined {
  return path === undefined ? undefined : readFileSync(path, "utf8");
}

/** Builds Node TLS connect options from {@link GelfTlsOptions}. */
export function tlsConnectOptions(host: string, tls: GelfTlsOptions): ConnectionOptions {
  const ca = [tls.caCertPem, pem(tls.caCertPath)].filter((v): v is string => v !== undefined);
  const out: ConnectionOptions = { rejectUnauthorized: tls.insecureSkipVerify !== true };
  if (ca.length > 0) out.ca = ca;
  const cert = pem(tls.clientCertPath);
  if (cert !== undefined) out.cert = cert;
  const key = pem(tls.clientKeyPath);
  if (key !== undefined) out.key = key;
  const servername = tls.servername ?? (/^[\d.]+$|:/.test(host) ? undefined : host);
  if (servername !== undefined) out.servername = servername;
  return out;
}

/**
 * GELF over TCP: one persistent connection, each message JSON + one NUL byte, optional TLS.
 * A failed connect or write closes the connection and retries the whole batch on a new one with
 * backoff (at-least-once: a batch may be delivered twice after a broken connection).
 */
export class GelfTcpTransport implements GelfTransport {
  readonly protocol = "tcp" as const;
  readonly host: string;
  readonly port: number;
  readonly connectTimeoutMs: number;
  readonly writeTimeoutMs: number;
  readonly retry: RetryPolicy;
  readonly #tls: ConnectionOptions | undefined;
  readonly #sleep: (ms: number, signal?: AbortSignal) => Promise<void>;
  #socket: Socket | null = null;
  #connecting: Promise<Socket> | null = null;
  #chain: Promise<unknown> = Promise.resolve();
  #closed = false;
  /** Connections opened so far (diagnostics, tests). */
  connections = 0;

  constructor(options: GelfTcpTransportOptions) {
    checkHost(options.host, "gelf.tcp");
    this.host = options.host;
    this.port = options.port ?? 12201;
    checkPort(this.port, "gelf.tcp");
    this.connectTimeoutMs = options.connectTimeoutMs ?? 10_000;
    this.writeTimeoutMs = options.writeTimeoutMs ?? 30_000;
    if (!(this.connectTimeoutMs > 0) || !(this.writeTimeoutMs > 0)) {
      throw new ConfigError("gelf.tcp: timeouts must be positive");
    }
    this.retry = RetryPolicy.from(options.retry);
    const tls = options.tls;
    this.#tls =
      tls === undefined || tls === false
        ? undefined
        : tlsConnectOptions(this.host, tls === true ? {} : tls);
    this.#sleep = options.sleep ?? abortableSleep;
  }

  /** Whether the transport uses TLS. */
  get secure(): boolean {
    return this.#tls !== undefined;
  }

  #connect(signal?: AbortSignal): Promise<Socket> {
    if (this.#socket !== null && !this.#socket.destroyed) return Promise.resolve(this.#socket);
    this.#connecting ??= new Promise<Socket>((resolve, reject) => {
      const onConnected = (): void => {
        cleanup();
        socket.setKeepAlive(true);
        socket.setNoDelay(true);
        socket.on("error", () => socket.destroy());
        socket.on("close", () => {
          if (this.#socket === socket) this.#socket = null;
        });
        socket.unref();
        this.#socket = socket;
        this.connections++;
        resolve(socket);
      };
      const socket: Socket =
        this.#tls === undefined
          ? netConnect({ host: this.host, port: this.port }, onConnected)
          : tlsConnect({ host: this.host, port: this.port, ...this.#tls }, onConnected);
      const timer = setTimeout(() => {
        fail(new TimeoutError(`gelf.tcp: connect timeout after ${this.connectTimeoutMs} ms`));
      }, this.connectTimeoutMs);
      const onError = (err: Error): void => {
        fail(networkError("gelf.tcp", err));
      };
      const onAbort = (): void => {
        fail(new CancelledError("gelf.tcp: cancelled"));
      };
      const cleanup = (): void => {
        clearTimeout(timer);
        socket.off("error", onError);
        signal?.removeEventListener("abort", onAbort);
      };
      const fail = (err: Error): void => {
        cleanup();
        socket.destroy();
        reject(err);
      };
      socket.once("error", onError);
      signal?.addEventListener("abort", onAbort, { once: true });
    }).finally(() => {
      this.#connecting = null;
    });
    return this.#connecting;
  }

  #write(socket: Socket, data: Uint8Array, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      let done = false;
      const finish = (err?: Error): void => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        socket.off("close", onClose);
        if (err === undefined) {
          resolve();
        } else {
          socket.destroy();
          reject(err);
        }
      };
      const onAbort = (): void => {
        finish(new CancelledError("gelf.tcp: cancelled"));
      };
      const onClose = (): void => {
        finish(new UnavailableError("gelf.tcp: connection closed"));
      };
      const timer = setTimeout(() => {
        finish(new TimeoutError(`gelf.tcp: write timeout after ${this.writeTimeoutMs} ms`));
      }, this.writeTimeoutMs);
      signal?.addEventListener("abort", onAbort, { once: true });
      socket.once("close", onClose);
      socket.write(data, (err) => {
        finish(err ? networkError("gelf.tcp", err) : undefined);
      });
    });
  }

  /** Encodes messages as NUL-terminated JSON frames. */
  static frame(messages: readonly GelfMessage[]): Uint8Array {
    return Buffer.from(messages.map((m) => m.toString() + "\0").join(""), "utf8");
  }

  send(messages: readonly GelfMessage[], options: GelfSendOptions = {}): Promise<GelfSendResult> {
    // Batches are written one after another so frames never interleave.
    const run = this.#chain.then(() => this.#send(messages, options.signal));
    this.#chain = run.catch(() => undefined);
    return run;
  }

  async #send(messages: readonly GelfMessage[], signal?: AbortSignal): Promise<GelfSendResult> {
    if (this.#closed) throw new ConfigError("gelf.tcp: transport is closed");
    if (messages.length === 0) return { sent: 0, rejected: 0 };
    const data = GelfTcpTransport.frame(messages);
    for (let attempt = 0; ; attempt++) {
      if (signal?.aborted === true) throw new CancelledError("gelf.tcp: cancelled");
      try {
        const socket = await this.#connect(signal);
        await this.#write(socket, data, signal);
        return { sent: messages.length, rejected: 0 };
      } catch (err) {
        const e = err as GraylogError;
        // close() may run while this send awaits
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
        if (e.code === "CANCELLED" || attempt >= this.retry.maxRetries || this.#closed) throw e;
        await this.#sleep(this.retry.backoffMs(attempt), signal).catch(() => {
          throw new CancelledError("gelf.tcp: cancelled");
        });
      }
    }
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await this.#chain;
    const socket = this.#socket;
    this.#socket = null;
    if (socket === null || socket.destroyed) return;
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        socket.destroy();
      }, 1000);
      socket.once("close", () => {
        clearTimeout(timer);
        resolve();
      });
      socket.end();
    });
  }
}

// ---- HTTP -----------------------------------------------------------------------------------

/** Options of {@link GelfHttpTransport}. */
export interface GelfHttpTransportOptions {
  /** Full endpoint, e.g. `http://graylog:12202/gelf`. */
  url: string;
  /** Gzip request bodies (`Content-Encoding: gzip`). Default true. */
  gzip?: boolean;
  /**
   * Send all messages of a batch as newline-delimited JSON in one request (input option
   * `enable_bulk_receiving`). When false, one request per message. Default true.
   */
  bulk?: boolean;
  /** Extra headers, e.g. the input's `authorization_header_name`/`value`. */
  headers?: Record<string, string>;
  /**
   * Timeouts, retry, TLS, proxy, hooks and logger (e.g. a {@link GraylogConfig}); `url` and
   * `headers` of this object are ignored.
   */
  config?: Partial<Omit<CommonConfig, "url" | "headers">>;
  /** Test seams of the HTTP transport. */
  internals?: Pick<TransportOptions, "dispatcher" | "sleep" | "now">;
}

/**
 * GELF over HTTP: `POST <url>` with JSON bodies, bulk (newline-delimited, every message
 * terminated by `\n`) and gzip by default.
 * Graylog answers 202 even for messages it drops, so messages are validated client side.
 * Retries, timeouts, TLS, proxy and hooks come from the shared HTTP transport.
 */
export class GelfHttpTransport implements GelfTransport {
  readonly protocol = "http" as const;
  readonly url: string;
  readonly gzip: boolean;
  readonly bulk: boolean;
  readonly #http: HttpTransport;
  readonly #headers: Record<string, string>;

  constructor(options: GelfHttpTransportOptions) {
    let parsed: URL;
    try {
      parsed = new URL(options.url);
    } catch {
      throw new ConfigError("gelf.http: url must be an http(s) URL");
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new ConfigError("gelf.http: url must be an http(s) URL");
    }
    this.url = options.url;
    this.gzip = options.gzip ?? true;
    this.bulk = options.bulk ?? true;
    this.#headers = { ...(options.headers ?? {}) };
    const base = options.config ?? {};
    const config = {
      ...base,
      url: options.url,
      connectTimeoutMs: base.connectTimeoutMs ?? 10_000,
      requestTimeoutMs: base.requestTimeoutMs ?? 30_000,
      totalTimeoutMs: base.totalTimeoutMs ?? 120_000,
      retry: base.retry ?? new RetryPolicy(),
      tls: base.tls ?? {},
      headers: {},
    } as CommonConfig;
    const headerSecrets = Object.values(this.#headers).filter((v) => v.length >= 4);
    this.#http = new HttpTransport({
      ...(options.internals ?? {}),
      config,
      knownSecrets: () => headerSecrets,
    });
  }

  async send(
    messages: readonly GelfMessage[],
    options: GelfSendOptions = {},
  ): Promise<GelfSendResult> {
    if (messages.length === 0) return { sent: 0, rejected: 0 };
    const gzip = options.gzip ?? this.gzip;
    const groups = this.bulk ? [messages] : messages.map((m) => [m]);
    let sent = 0;
    for (const group of groups) {
      // Every message ends with "\n": Graylog 7.0 drops the first message of a later request on
      // a kept-alive connection when the previous body did not end with a newline.
      const text = group.map((m) => m.toString() + "\n").join("");
      const headers: Record<string, string> = {
        ...this.#headers,
        "content-type": "application/json",
      };
      let body: Uint8Array | string = text;
      if (gzip) {
        body = gzipSync(Buffer.from(text, "utf8"));
        headers["content-encoding"] = "gzip";
      }
      await this.#http.request({
        method: "POST",
        path: this.url,
        headers,
        body,
        responseType: "none",
        operation: "gelf.http",
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      sent += group.length;
    }
    return { sent, rejected: 0 };
  }

  close(): Promise<void> {
    return this.#http.close();
  }
}

// ---- exporter -------------------------------------------------------------------------------

/**
 * {@link LogExporter} that converts records with {@link GelfMessage.fromLogRecord} and sends them
 * through a {@link GelfTransport}. Use it with `BatchingLogClient` (or `client.logClient()`).
 */
export class GelfLogExporter implements LogExporter {
  readonly transport: GelfTransport;
  readonly #options: FromLogRecordOptions;

  constructor(transport: GelfTransport, options: FromLogRecordOptions = {}) {
    this.transport = transport;
    this.#options = options;
  }

  async export(records: LogRecord[], opts: ExportOptions): Promise<ExportResult> {
    const messages = records.map((r) => GelfMessage.fromLogRecord(r, this.#options));
    const result = await this.transport.send(messages, {
      gzip: opts.gzip,
      ...(opts.signal === undefined ? {} : { signal: opts.signal }),
    });
    const out: ExportResult = { accepted: result.sent, rejected: result.rejected };
    if (result.error !== undefined) out.error = result.error;
    return out;
  }

  shutdown(): Promise<void> {
    return this.transport.close();
  }
}
