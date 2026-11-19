// Service-owned: the Graylog Open client (REST admin + search, GELF/OTLP log clients).

import {
  CancelledError,
  ConflictError,
  type HealthStatus,
  HttpTransport,
  TimeoutError,
  type TransportOptions,
  UnsupportedError,
  ValidationError,
  healthStatus,
  pollUntil,
  probeHealth,
} from "./core/index.js";
import { GraylogConfig, type GelfProtocol, type GraylogConfigOptions, bareHost } from "./config.js";
import {
  GelfHttpTransport,
  GelfLogExporter,
  GelfTcpTransport,
  GelfUdpTransport,
  type GelfCompression,
  type GelfTransport,
} from "./gelf-transports.js";
import {
  BatchingLogClient,
  type BatchingLogClientOptions,
  type LogClient,
} from "./logging/index.js";
import {
  GELF_INPUT_TYPES,
  type GraylogInput,
  type GraylogMessage,
  type GraylogStream,
  type IndexSet,
  type InputState,
  type SearchResult,
  type StreamPage,
  type StreamRule,
  type SystemInfo,
  dateOrNull,
  decodeIndexSet,
  decodeInput,
  decodeInputState,
  decodeMessage,
  decodeStream,
  decodeSystemInfo,
  expectObject,
} from "./models.js";
import { OtlpGrpcLogExporter } from "./otlp.js";
import { GraylogLogQueryClient, type GraylogLogQueryClientOptions } from "./query-client.js";

/** Per-call options. */
export interface CallOptions {
  /** Cancels the call (`CancelledError`). */
  signal?: AbortSignal;
}

/** Test seams (undici `MockAgent`, fake sleep). Not part of the stable API. */
export type ClientInternals = Pick<TransportOptions, "dispatcher" | "sleep" | "now">;

/** Sort order of search results. */
export interface SearchSort {
  field: string;
  /** Default `desc`. */
  order?: "asc" | "desc";
}

/** Options of {@link GraylogClient.search}. Give at most one of `range`, `from`/`to`, `keyword`. */
export interface SearchOptions extends CallOptions {
  /** Relative range in seconds (default 300 when no other range is given). */
  range?: number;
  /** Absolute range start (default `to` − 300 s). */
  from?: Date;
  /** Absolute range end (default now). */
  to?: Date;
  /** Graylog keyword range, e.g. `"last five minutes"`. */
  keyword?: string;
  /** Messages per page, 1..10000. Default 100. */
  limit?: number;
  /** Messages to skip. Default 0. */
  offset?: number;
  /** Only return these fields (plus `_id`). */
  fields?: readonly string[];
  /** Sort. Default `{ field: "timestamp", order: "desc" }`; an array adds tie-breakers. */
  sort?: SearchSort | readonly SearchSort[];
  /** Stream ids to search (default: every stream the user may read). */
  streams?: readonly string[];
}

/** Options of {@link GraylogClient.searchRelative}. */
export type SearchRelativeOptions = Omit<SearchOptions, "range" | "from" | "to" | "keyword">;

/** Options of {@link GraylogClient.createInput}. */
export interface CreateInputOptions extends CallOptions {
  /** Default `"<type name> (grow-codes)"`. */
  title?: string;
  /** Run on every node. Default true. */
  global?: boolean;
  /** Node id for a node-local input (`global: false`). */
  node?: string;
}

/** Options of {@link GraylogClient.ensureGelfInput}. */
export interface EnsureGelfInputOptions extends CallOptions {
  /** Title of a new input. Default `"grow-codes GELF <PROTOCOL> <port>"`. */
  title?: string;
  /** Default `0.0.0.0`. */
  bindAddress?: string;
  /** Extra input configuration merged over the defaults (e.g. `tls_enable`). */
  configuration?: Record<string, unknown>;
  /** How long to wait for the input to be `RUNNING`. Default 30 000 ms. */
  timeoutMs?: number;
  /** Poll interval. Default 500 ms. */
  intervalMs?: number;
}

/** Result of {@link GraylogClient.ensureGelfInput}. */
export interface EnsuredInput extends GraylogInput {
  /** Whether this call created the input. */
  created: boolean;
}

/** Options of {@link GraylogClient.listStreams}. */
export interface ListStreamsOptions extends CallOptions {
  /** 1-based page. Default 1. */
  page?: number;
  /** Default 50. */
  perPage?: number;
  /** Search text (title/description). */
  query?: string;
  /** Default `title`. */
  sort?: string;
  /** Default `asc`. */
  order?: "asc" | "desc";
}

/** Options of {@link GraylogClient.createStream}. */
export interface CreateStreamOptions extends CallOptions {
  title: string;
  description?: string;
  /** Default: the default index set. */
  indexSetId?: string;
  rules?: readonly Omit<StreamRule, "id">[];
  /** `AND` (default) or `OR`. */
  matchingType?: "AND" | "OR";
  /** Default false. */
  removeMatchesFromDefaultStream?: boolean;
  /** Resume (start) the stream after creating it; Graylog creates streams paused. Default true. */
  start?: boolean;
}

/** Options of {@link GraylogClient.logClient}. */
export interface GraylogLogClientOptions extends BatchingLogClientOptions {
  /** Transport. Default: `config.gelfProtocol`. `otlp` uses the OpenTelemetry (gRPC) input. */
  protocol?: GelfProtocol | "otlp";
  /** GELF `host` for records without `resource["host.name"]`. Default `os.hostname()`. */
  host?: string;
  /** Use this transport instead of building one (it is closed with the log client). */
  transport?: GelfTransport;
  /** UDP payload compression. Default `gzip`. */
  compression?: GelfCompression;
  /** UDP chunk size. Default 1420. */
  chunkSize?: number;
  /** HTTP: bulk (newline-delimited) bodies. Default true. */
  bulk?: boolean;
  /** HTTP/OTLP: extra headers (e.g. input authorization header). */
  headers?: Record<string, string>;
  /** OTLP: bearer token configured on the input. */
  bearerToken?: string;
}

const TIMESTAMP_DESC: readonly SearchSort[] = [{ field: "timestamp", order: "desc" }];

function seg(value: string, what: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new ValidationError(`${what} must not be empty`);
  }
  return encodeURIComponent(value);
}

function checkInt(value: number | undefined, name: string, min: number, max: number): void {
  if (value !== undefined && (!Number.isInteger(value) || value < min || value > max)) {
    throw new ValidationError(`${name} must be an integer ${min}..${max}`);
  }
}

function gelfInputConfiguration(
  protocol: GelfProtocol,
  port: number,
  bindAddress: string,
): Record<string, unknown> {
  const common = {
    bind_address: bindAddress,
    port,
    number_worker_threads: 2,
    decompress_size_limit: 8_388_608,
  };
  switch (protocol) {
    case "udp":
      return { ...common, recv_buffer_size: 262_144 };
    case "tcp":
      return {
        ...common,
        recv_buffer_size: 1_048_576,
        tls_enable: false,
        tcp_keepalive: false,
        use_null_delimiter: true,
        max_message_size: 2_097_152,
      };
    case "http":
      return {
        ...common,
        recv_buffer_size: 1_048_576,
        tls_enable: false,
        tcp_keepalive: false,
        enable_bulk_receiving: true,
        enable_cors: true,
        max_chunk_size: 8_388_608,
        idle_writer_timeout: 60,
      };
  }
}

/**
 * Client for Graylog Open: health, REST admin (inputs, streams, index sets), search, and log
 * clients that send through GELF (UDP, TCP, HTTP) or OTLP/gRPC.
 */
export class GraylogClient {
  /** The immutable configuration. */
  readonly config: GraylogConfig;
  readonly #http: HttpTransport;
  readonly #internals: ClientInternals;
  readonly #logClients = new Set<LogClient>();
  #closed = false;

  /** Accepts a {@link GraylogConfig} or plain options. */
  constructor(config: GraylogConfigOptions = {}, internals: ClientInternals = {}) {
    const cfg = GraylogConfig.from(config);
    this.config = cfg;
    this.#internals = internals;
    this.#http = new HttpTransport({
      ...internals,
      config: cfg,
      defaultHeaders: (): Record<string, string> => {
        const auth = cfg.authorizationHeader();
        return {
          "x-requested-by": cfg.requestedBy,
          ...(auth === undefined ? {} : { authorization: auth }),
        };
      },
      knownSecrets: () => cfg.knownSecrets(),
    });
  }

  /** Builds a client from `GROW_GRAYLOG_*` (and vendor) environment variables. */
  static fromEnv(overrides: GraylogConfigOptions = {}): GraylogClient {
    return new GraylogClient(GraylogConfig.fromEnv(overrides));
  }

  /** Every REST call on a closed client fails with `CANCELLED` (same in all five languages). */
  get #transport(): HttpTransport {
    if (this.#closed) throw new CancelledError("graylog: client is closed");
    return this.#http;
  }

  /** True once {@link close} was called. */
  get closed(): boolean {
    return this.#closed;
  }

  /** The shared HTTP transport (for service modules). @internal */
  get transport(): HttpTransport {
    return this.#http;
  }

  // ---- client surface ---------------------------------------------------------------------

  /**
   * Unauthenticated liveness: `GET /api/system/lbstatus`. `ALIVE` → healthy `ok`, 429
   * `THROTTLED` → `degraded`, 503 `DEAD` → `unhealthy`. Never throws for an unhealthy or
   * unreachable service (only `CANCELLED` and `CONFIG`).
   */
  health(options: CallOptions = {}): Promise<HealthStatus> {
    return probeHealth(async () => {
      const res = await this.#transport.get<string | undefined>("/api/system/lbstatus", {
        operation: "health",
        headers: { accept: "text/plain" },
        responseType: "text",
        allowStatus: [429, 503],
        ...options,
      });
      if (res.status === 429) return healthStatus("degraded", { lb_status: "THROTTLED" }, false);
      if (res.status === 503) return healthStatus("unhealthy", { lb_status: "DEAD" }, false);
      const word = (res.data ?? "").trim().toUpperCase();
      return word === "ALIVE"
        ? healthStatus("ok", { lb_status: word }, true)
        : healthStatus("unhealthy", { lb_status: word }, false);
    });
  }

  /** Authenticated round trip: `GET /api/system`. Returns the latency in milliseconds. */
  async ping(options: CallOptions = {}): Promise<number> {
    const start = performance.now();
    await this.#transport.get("/api/system", { operation: "ping", ...options });
    return performance.now() - start;
  }

  /** Server version as reported by `GET /api/system`, e.g. `7.0.16+58e0f6e`. */
  async serverVersion(options: CallOptions = {}): Promise<string> {
    const info = await this.systemInfo(options);
    if (info.version === "") {
      throw new UnsupportedError("serverVersion: the service does not report a version");
    }
    return info.version;
  }

  /** Node and cluster information: `GET /api/system`. */
  async systemInfo(options: CallOptions = {}): Promise<SystemInfo> {
    const res = await this.#transport.get("/api/system", { operation: "systemInfo", ...options });
    return decodeSystemInfo(expectObject(res.data, "systemInfo"));
  }

  // ---- inputs -------------------------------------------------------------------------------

  /** Every configured input: `GET /api/system/inputs`. */
  async listInputs(options: CallOptions = {}): Promise<GraylogInput[]> {
    const res = await this.#transport.get("/api/system/inputs", {
      operation: "listInputs",
      ...options,
    });
    const body = expectObject(res.data, "listInputs");
    return Array.isArray(body.inputs) ? body.inputs.map(decodeInput) : [];
  }

  /** One input: `GET /api/system/inputs/{id}`; `NotFoundError` when unknown. */
  async getInput(id: string, options: CallOptions = {}): Promise<GraylogInput> {
    const res = await this.#transport.get(`/api/system/inputs/${seg(id, "getInput: id")}`, {
      operation: "getInput",
      ...options,
    });
    return decodeInput(expectObject(res.data, "getInput"));
  }

  /** Runtime state of an input: `GET /api/system/inputstates/{id}`. */
  async getInputState(id: string, options: CallOptions = {}): Promise<InputState> {
    const res = await this.#transport.get(
      `/api/system/inputstates/${seg(id, "getInputState: id")}`,
      { operation: "getInputState", ...options },
    );
    return decodeInputState(expectObject(res.data, "getInputState"));
  }

  /** Installed input types, class name → human name: `GET /api/system/inputs/types`. */
  async listInputTypes(options: CallOptions = {}): Promise<Record<string, string>> {
    const res = await this.#transport.get("/api/system/inputs/types", {
      operation: "listInputTypes",
      ...options,
    });
    const types = expectObject(res.data, "listInputTypes").types;
    const out: Record<string, string> = {};
    if (types !== null && typeof types === "object") {
      for (const [k, v] of Object.entries(types)) out[k] = String(v);
    }
    return out;
  }

  /**
   * Creates an input: `POST /api/system/inputs`. Returns its id. Unknown types raise
   * `NotFoundError`. Graylog does not reject a busy port here: check {@link getInputState}
   * (or use {@link ensureGelfInput}).
   */
  async createInput(
    type: string,
    configuration: Record<string, unknown>,
    options: CreateInputOptions = {},
  ): Promise<string> {
    if (typeof type !== "string" || type.trim() === "") {
      throw new ValidationError("createInput: type must not be empty");
    }
    const short = type.split(".").pop() ?? type;
    const body: Record<string, unknown> = {
      title: options.title ?? `${short} (grow-codes)`,
      type,
      global: options.global ?? true,
      configuration,
    };
    if (options.node !== undefined) body.node = options.node;
    const res = await this.#transport.post("/api/system/inputs", {
      operation: "createInput",
      json: body,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    const id = expectObject(res.data, "createInput").id;
    if (typeof id !== "string") throw new ValidationError("createInput: response without id");
    return id;
  }

  /**
   * Returns a running GELF input for `protocol` and `port`, creating it when none exists
   * (matched by type, port and bind address). Waits until the input is `RUNNING`; a `FAILED`
   * input (e.g. port in use) raises `ConflictError` and an input created by this call is deleted
   * again. `TimeoutError` after `timeoutMs`.
   */
  async ensureGelfInput(
    protocol: GelfProtocol,
    port: number,
    options: EnsureGelfInputOptions = {},
  ): Promise<EnsuredInput> {
    const type = GELF_INPUT_TYPES[protocol] as string | undefined;
    if (type === undefined) {
      throw new ValidationError("ensureGelfInput: protocol must be udp, tcp or http");
    }
    checkInt(port, "ensureGelfInput: port", 1, 65_535);
    const bindAddress = options.bindAddress ?? "0.0.0.0";
    const call = options.signal === undefined ? {} : { signal: options.signal };
    const match = (inputs: GraylogInput[]): GraylogInput | undefined =>
      inputs.find(
        (i) =>
          i.type === type &&
          i.port === port &&
          (i.bindAddress === null || i.bindAddress === bindAddress),
      );
    let input = match(await this.listInputs(call));
    let created = false;
    if (input === undefined) {
      const configuration = {
        ...gelfInputConfiguration(protocol, port, bindAddress),
        ...(options.configuration ?? {}),
      };
      const id = await this.createInput(type, configuration, {
        title: options.title ?? `grow-codes GELF ${protocol.toUpperCase()} ${port}`,
        ...call,
      });
      created = true;
      input =
        (await this.listInputs(call)).find((i) => i.id === id) ?? (await this.getInput(id, call));
    }
    const id = input.id;
    let state: InputState;
    try {
      state = await pollUntil(
        async () => {
          const res = await this.#transport.get(`/api/system/inputstates/${seg(id, "id")}`, {
            operation: "ensureGelfInput",
            allowStatus: [404],
            ...call,
          });
          return res.status === 404 ? null : decodeInputState(res.data);
        },
        (s) => s !== null && (s.state === "RUNNING" || s.state === "FAILED"),
        {
          timeoutMs: options.timeoutMs ?? 30_000,
          intervalMs: options.intervalMs ?? 500,
          operation: `ensureGelfInput ${protocol}:${port}`,
          ...call,
        },
      ).then((s) => s as InputState);
    } catch (err) {
      if (err instanceof TimeoutError && created)
        await this.deleteInput(id, call).catch(() => undefined);
      throw err;
    }
    if (state.state === "FAILED") {
      if (created) await this.deleteInput(id, call).catch(() => undefined);
      throw new ConflictError(
        `ensureGelfInput ${protocol}:${port}: input failed to start${state.detailedMessage === null ? "" : `: ${this.#http.redact(state.detailedMessage).slice(0, 300)}`}`,
      );
    }
    return { ...input, created };
  }

  /** Deletes an input: `DELETE /api/system/inputs/{id}`; `NotFoundError` when unknown. */
  async deleteInput(id: string, options: CallOptions = {}): Promise<void> {
    await this.#transport.delete(`/api/system/inputs/${seg(id, "deleteInput: id")}`, {
      operation: "deleteInput",
      responseType: "none",
      ...options,
    });
  }

  // ---- streams and index sets ---------------------------------------------------------------

  /** One page of streams: `GET /api/streams/paginated`. */
  async listStreams(options: ListStreamsOptions = {}): Promise<StreamPage> {
    checkInt(options.page, "listStreams: page", 1, Number.MAX_SAFE_INTEGER);
    checkInt(options.perPage, "listStreams: perPage", 1, 10_000);
    const res = await this.#transport.get("/api/streams/paginated", {
      operation: "listStreams",
      query: {
        page: options.page ?? 1,
        per_page: options.perPage ?? 50,
        sort: options.sort ?? "title",
        order: options.order ?? "asc",
        query: options.query === undefined || options.query === "" ? undefined : options.query,
      },
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    const body = expectObject(res.data, "listStreams");
    const pagination = (body.pagination ?? {}) as Record<string, unknown>;
    const streams = Array.isArray(body.elements) ? body.elements.map(decodeStream) : [];
    const n = (v: unknown, d: number): number => (typeof v === "number" ? v : d);
    return {
      streams,
      total: n(pagination.total, n(body.total, streams.length)),
      page: n(pagination.page, options.page ?? 1),
      perPage: n(pagination.per_page, options.perPage ?? 50),
    };
  }

  /** One stream: `GET /api/streams/{id}`; `NotFoundError` when unknown. */
  async getStream(id: string, options: CallOptions = {}): Promise<GraylogStream> {
    const res = await this.#transport.get(`/api/streams/${seg(id, "getStream: id")}`, {
      operation: "getStream",
      ...options,
    });
    return decodeStream(expectObject(res.data, "getStream"));
  }

  /**
   * Creates a stream (`POST /api/streams`) in the given (default: the default) index set and
   * resumes it unless `start: false` (Graylog creates streams paused). Returns the stream id.
   */
  async createStream(options: CreateStreamOptions): Promise<string> {
    if (typeof options.title !== "string" || options.title.trim() === "") {
      throw new ValidationError("createStream: title must not be empty");
    }
    const call = options.signal === undefined ? {} : { signal: options.signal };
    let indexSetId = options.indexSetId;
    if (indexSetId === undefined) {
      const sets = await this.listIndexSets(call);
      indexSetId = (sets.find((s) => s.isDefault) ?? sets[0])?.id;
      if (indexSetId === undefined) {
        throw new ValidationError("createStream: no index set available");
      }
    }
    const entity = {
      title: options.title,
      description: options.description ?? "",
      index_set_id: indexSetId,
      matching_type: options.matchingType ?? "AND",
      remove_matches_from_default_stream: options.removeMatchesFromDefaultStream ?? false,
      rules: (options.rules ?? []).map((r) => ({
        field: r.field,
        type: r.type,
        value: r.value,
        inverted: r.inverted,
        description: r.description,
      })),
    };
    const res = await this.#transport.post("/api/streams", {
      operation: "createStream",
      json: { entity },
      ...call,
    });
    const id = expectObject(res.data, "createStream").stream_id;
    if (typeof id !== "string")
      throw new ValidationError("createStream: response without stream_id");
    if (options.start ?? true) await this.resumeStream(id, call);
    return id;
  }

  /** Starts (resumes) a paused stream: `POST /api/streams/{id}/resume`. */
  async resumeStream(id: string, options: CallOptions = {}): Promise<void> {
    await this.#transport.post(`/api/streams/${seg(id, "resumeStream: id")}/resume`, {
      operation: "resumeStream",
      responseType: "none",
      idempotent: true,
      ...options,
    });
  }

  /** Deletes a stream: `DELETE /api/streams/{id}`; `NotFoundError` when unknown. */
  async deleteStream(id: string, options: CallOptions = {}): Promise<void> {
    await this.#transport.delete(`/api/streams/${seg(id, "deleteStream: id")}`, {
      operation: "deleteStream",
      responseType: "none",
      ...options,
    });
  }

  /** Every index set: `GET /api/system/indices/index_sets?skip_stats=true`. */
  async listIndexSets(options: CallOptions = {}): Promise<IndexSet[]> {
    const res = await this.#transport.get("/api/system/indices/index_sets", {
      operation: "listIndexSets",
      query: { skip_stats: true },
      ...options,
    });
    const body = expectObject(res.data, "listIndexSets");
    return Array.isArray(body.index_sets) ? body.index_sets.map(decodeIndexSet) : [];
  }

  // ---- search -------------------------------------------------------------------------------

  /**
   * Searches messages with a Lucene query (`POST /api/views/search/sync`). Query errors (HTTP 200
   * with `errors`) raise `ValidationError`. An empty query matches everything.
   */
  async search(query: string, options: SearchOptions = {}): Promise<SearchResult> {
    const timerange = this.#timerange(options);
    checkInt(options.limit, "search: limit", 1, 10_000);
    checkInt(options.offset, "search: offset", 0, Number.MAX_SAFE_INTEGER);
    const sorts: readonly SearchSort[] =
      options.sort === undefined
        ? TIMESTAMP_DESC
        : Array.isArray(options.sort)
          ? (options.sort as readonly SearchSort[])
          : [options.sort as SearchSort];
    const searchType: Record<string, unknown> = {
      id: "st1",
      type: "messages",
      limit: options.limit ?? 100,
      offset: options.offset ?? 0,
      sort: sorts.map((s) => ({ field: s.field, order: (s.order ?? "desc").toUpperCase() })),
    };
    if (options.fields !== undefined && options.fields.length > 0)
      searchType.fields = [...options.fields];
    const q: Record<string, unknown> = {
      id: "q1",
      query: {
        type: "elasticsearch",
        query_string: typeof query === "string" && query.trim() !== "" ? query : "*",
      },
      timerange,
      search_types: [searchType],
    };
    if (options.streams !== undefined && options.streams.length > 0) {
      q.filter = {
        type: "or",
        filters: options.streams.map((id) => ({ type: "stream", id })),
      };
    }
    const res = await this.#transport.post("/api/views/search/sync", {
      operation: "search",
      json: { queries: [q] },
      idempotent: true,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    return this.#decodeSearch(expectObject(res.data, "search"), options.offset ?? 0);
  }

  /** {@link search} over the last `seconds` seconds (relative range). */
  searchRelative(
    query: string,
    seconds: number,
    options: SearchRelativeOptions = {},
  ): Promise<SearchResult> {
    return this.search(query, { ...options, range: seconds });
  }

  #timerange(options: SearchOptions): Record<string, unknown> {
    const kinds =
      (options.range !== undefined ? 1 : 0) +
      (options.from !== undefined || options.to !== undefined ? 1 : 0) +
      (options.keyword !== undefined ? 1 : 0);
    if (kinds > 1) {
      throw new ValidationError("search: give only one of range, from/to and keyword");
    }
    if (options.from !== undefined || options.to !== undefined) {
      const to = options.to ?? new Date();
      const from = options.from ?? new Date(to.getTime() - 300_000);
      if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) {
        throw new ValidationError("search: invalid from/to date");
      }
      if (from.getTime() > to.getTime()) throw new ValidationError("search: from is after to");
      return { type: "absolute", from: from.toISOString(), to: to.toISOString() };
    }
    if (options.keyword !== undefined) {
      if (options.keyword.trim() === "")
        throw new ValidationError("search: keyword must not be empty");
      return { type: "keyword", keyword: options.keyword };
    }
    const range = options.range ?? 300;
    checkInt(range, "search: range (seconds)", 1, Number.MAX_SAFE_INTEGER);
    return { type: "relative", range };
  }

  #decodeSearch(body: Record<string, unknown>, offset: number): SearchResult {
    const results = (body.results ?? {}) as Record<string, Record<string, unknown> | undefined>;
    const q1 = results.q1 ?? {};
    const errors = [
      ...(Array.isArray(body.errors) ? (body.errors as unknown[]) : []),
      ...(Array.isArray(q1.errors) ? (q1.errors as unknown[]) : []),
    ] as { description?: unknown }[];
    const execution = (body.execution ?? {}) as { completed_exceptionally?: unknown };
    if (errors.length > 0 || execution.completed_exceptionally === true) {
      const description = errors.map((e) => e.description).find((d) => typeof d === "string");
      const text = this.#http.redact(
        typeof description === "string" ? description : "query failed",
      );
      throw new ValidationError(`search: ${text.slice(0, 300)}`);
    }
    const st =
      ((q1.search_types ?? {}) as Record<string, Record<string, unknown> | undefined>).st1 ?? {};
    const raw = Array.isArray(st.messages) ? (st.messages as Record<string, unknown>[]) : [];
    const messages: GraylogMessage[] = raw.map((m) => decodeMessage(m.message, m.index));
    const total = typeof st.total_results === "number" ? st.total_results : messages.length;
    const stats = (q1.execution_stats ?? {}) as Record<string, unknown>;
    const range = (st.effective_timerange ?? stats.effective_timerange ?? {}) as Record<
      string,
      unknown
    >;
    const out: SearchResult = {
      messages,
      total,
      from: dateOrNull(range.from),
      to: dateOrNull(range.to),
    };
    if (messages.length > 0 && offset + messages.length < total)
      out.nextOffset = offset + messages.length;
    return out;
  }

  /** One stored message: `GET /api/messages/{index}/{id}`; `NotFoundError` when unknown. */
  async getMessage(index: string, id: string, options: CallOptions = {}): Promise<GraylogMessage> {
    const res = await this.#transport.get(
      `/api/messages/${seg(index, "getMessage: index")}/${seg(id, "getMessage: id")}`,
      { operation: "getMessage", ...options },
    );
    const body = expectObject(res.data, "getMessage");
    const message = (body.message ?? {}) as Record<string, unknown>;
    return decodeMessage(message.fields ?? {}, body.index);
  }

  /** Every indexed field name: `GET /api/system/fields`. */
  async listFields(options: CallOptions = {}): Promise<string[]> {
    const res = await this.#transport.get("/api/system/fields", {
      operation: "listFields",
      ...options,
    });
    const fields = expectObject(res.data, "listFields").fields;
    return Array.isArray(fields)
      ? fields.filter((f): f is string => typeof f === "string").sort()
      : [];
  }

  // ---- logging ------------------------------------------------------------------------------

  /** Builds a GELF transport from the configuration (default protocol: `config.gelfProtocol`). */
  gelfTransport(
    protocol: GelfProtocol = this.config.gelfProtocol,
    options: Pick<GraylogLogClientOptions, "compression" | "chunkSize" | "bulk" | "headers"> = {},
  ): GelfTransport {
    const cfg = this.config;
    switch (protocol) {
      case "udp":
        return new GelfUdpTransport({
          host: cfg.gelfHost,
          port: cfg.gelfPortFor("udp"),
          ...(options.compression === undefined ? {} : { compression: options.compression }),
          ...(options.chunkSize === undefined ? {} : { chunkSize: options.chunkSize }),
        });
      case "tcp":
        return new GelfTcpTransport({
          host: bareHost(cfg.gelfHost),
          port: cfg.gelfPortFor("tcp"),
          connectTimeoutMs: cfg.connectTimeoutMs,
          writeTimeoutMs: cfg.requestTimeoutMs,
          retry: cfg.retry,
          ...(cfg.gelfTls ? { tls: { ...cfg.tls } } : {}),
        });
      case "http":
        return new GelfHttpTransport({
          url: cfg.gelfHttpEndpoint(),
          config: cfg,
          internals: this.#internals,
          ...(options.bulk === undefined ? {} : { bulk: options.bulk }),
          ...(options.headers === undefined ? {} : { headers: options.headers }),
        });
      default:
        throw new ValidationError("gelfTransport: protocol must be udp, tcp or http");
    }
  }

  /**
   * A batching {@link LogClient} that sends through GELF (`udp`, `tcp`, `http`) or OTLP/gRPC
   * (`otlp`). Closed (flushed) by {@link close}.
   */
  logClient(options: GraylogLogClientOptions = {}): LogClient {
    if (this.#closed) throw new CancelledError("logClient: client is closed");
    const protocol = options.protocol ?? this.config.gelfProtocol;
    const exporter =
      protocol === "otlp"
        ? new OtlpGrpcLogExporter({
            endpoint: this.config.otlpGrpcEndpoint(),
            timeoutMs: this.config.requestTimeoutMs,
            connectTimeoutMs: this.config.connectTimeoutMs,
            tls: { ...this.config.tls },
            ...(options.bearerToken === undefined ? {} : { bearerToken: options.bearerToken }),
            ...(options.headers === undefined ? {} : { headers: options.headers }),
          })
        : new GelfLogExporter(
            options.transport ?? this.gelfTransport(protocol, options),
            options.host === undefined ? {} : { host: options.host },
          );
    const client = new BatchingLogClient(exporter, options);
    this.#logClients.add(client);
    return client;
  }

  /** A {@link GraylogLogQueryClient} (search, polling tail, streams, fields). */
  logQueryClient(options: GraylogLogQueryClientOptions = {}): GraylogLogQueryClient {
    return new GraylogLogQueryClient(this, options);
  }

  /** Flushes and closes every log client created by {@link logClient}, then releases connections. Idempotent. */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    const clients = [...this.#logClients];
    this.#logClients.clear();
    await Promise.all(clients.map((c) => c.close().catch(() => undefined)));
    await this.#http.close();
  }
}
