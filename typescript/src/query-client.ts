// Service-owned: LogQueryClient for Graylog (views search, polling tail, streams, fields).

import { ValidationError } from "./core/index.js";
import type { GraylogClient, SearchSort } from "./client.js";
import { logRecordFromMessage } from "./gelf.js";
import {
  BaseLogQueryClient,
  pollTail,
  type LogRecord,
  type LogSearchOptions,
  type LogSearchResult,
  type TailHandle,
  type TailOptions,
} from "./logging/index.js";

/** Default poll interval of {@link GraylogLogQueryClient.tail} (decision 1). */
export const DEFAULT_TAIL_INTERVAL_MS = 2000;

/** Options of {@link GraylogLogQueryClient}. */
export interface GraylogLogQueryClientOptions {
  /** Stream ids every search is limited to (default: every readable stream). */
  streams?: readonly string[];
  /** Search window when `start` is not given: `end` minus this. Default 3 600 000 ms (1 h). */
  defaultWindowMs?: number;
}

/**
 * {@link LogQueryClient} on top of {@link GraylogClient.search}: absolute time range, timestamp
 * order (ties broken by `gl2_message_id`), offset cursors, hits normalised into log records.
 * Graylog has no streaming API: {@link tail} polls every 2 s.
 */
export class GraylogLogQueryClient extends BaseLogQueryClient {
  readonly #client: GraylogClient;
  readonly #streams: readonly string[] | undefined;
  readonly #windowMs: number;

  constructor(client: GraylogClient, options: GraylogLogQueryClientOptions = {}) {
    super();
    this.#client = client;
    this.#streams = options.streams;
    this.#windowMs = options.defaultWindowMs ?? 3_600_000;
    if (!(this.#windowMs > 0)) {
      throw new ValidationError("logQueryClient: defaultWindowMs must be positive");
    }
  }

  async search(query: string, opts: LogSearchOptions = {}): Promise<LogSearchResult> {
    const end = opts.end ?? new Date();
    const start = opts.start ?? new Date(end.getTime() - this.#windowMs);
    let offset = 0;
    if (opts.cursor !== undefined) {
      if (!/^\d+$/.test(opts.cursor)) {
        throw new ValidationError("logging.search: invalid cursor");
      }
      offset = Number(opts.cursor);
    }
    const order = opts.order ?? "desc";
    const sort: SearchSort[] = [
      { field: "timestamp", order },
      { field: "gl2_message_id", order },
    ];
    const result = await this.#client.search(query, {
      from: start,
      to: end,
      limit: opts.limit ?? 100,
      offset,
      sort,
      ...(this.#streams === undefined ? {} : { streams: this.#streams }),
      ...(opts.signal === undefined ? {} : { signal: opts.signal }),
    });
    const out: LogSearchResult = {
      records: result.messages.map((m) => logRecordFromMessage(m.fields)),
      total: result.total,
    };
    if (result.nextOffset !== undefined) out.nextCursor = String(result.nextOffset);
    return out;
  }

  override tail(
    query: string,
    onRecord: (record: LogRecord) => void,
    opts: TailOptions = {},
  ): TailHandle {
    return pollTail(this, query, onRecord, {
      ...opts,
      intervalMs: opts.intervalMs ?? DEFAULT_TAIL_INTERVAL_MS,
    });
  }

  /** Titles of every stream (all pages). */
  override async listStreams(): Promise<string[]> {
    const titles: string[] = [];
    for (let page = 1; ; page++) {
      const result = await this.#client.listStreams({ page, perPage: 100 });
      titles.push(...result.streams.map((s) => s.title));
      if (result.streams.length === 0 || titles.length >= result.total) return titles;
    }
  }

  /** Every indexed field name. */
  override listLabels(): Promise<string[]> {
    return this.#client.listFields();
  }
}
