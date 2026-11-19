// Service-owned: LogQueryClient for Graylog (views search, polling tail, streams, fields).

import { CancelledError, ValidationError } from "./core/index.js";
import type { GraylogClient, SearchSort } from "./client.js";
import { logRecordFromMessage } from "./gelf.js";
import {
  BaseLogQueryClient,
  type LogRecord,
  type LogSearchOptions,
  type LogSearchResult,
  type TailHandle,
  type TailOptions,
} from "./logging/index.js";

/** Default poll interval of {@link GraylogLogQueryClient.tail} (decision 1). */
export const DEFAULT_TAIL_INTERVAL_MS = 2000;

/**
 * How far back each tail poll looks before the newest record seen, so records that become
 * searchable late (ingest takes 1–2 s) are not missed; duplicates are dropped by message id.
 */
export const TAIL_OVERLAP_MS = 10_000;

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
 * Graylog has no streaming API: {@link tail} polls every 2 s with a 10 s look-back window.
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

  /**
   * Polls search every `opts.intervalMs` (default 2 s; Graylog has no streaming API) and calls
   * `onRecord` once per new matching record, oldest first, starting at `opts.start` (default now).
   * Each poll looks back {@link TAIL_OVERLAP_MS} before the newest record seen and drops duplicates
   * by message id, so late records are delivered too. Search errors go to `opts.onError` and
   * polling continues. The tail stops with the handle or when the client is closed. Throws
   * `CancelledError` on a closed client.
   */
  override tail(
    query: string,
    onRecord: (record: LogRecord) => void,
    opts: TailOptions = {},
  ): TailHandle {
    const client = this.#client;
    if (client.closed) throw new CancelledError("logs.tail: client is closed");
    const intervalMs =
      opts.intervalMs !== undefined && opts.intervalMs > 0
        ? opts.intervalMs
        : DEFAULT_TAIL_INTERVAL_MS;
    const since = (opts.start ?? new Date()).getTime();
    const streams = this.#streams;
    const seen = new Map<string, number>();
    let newest: number | undefined;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const controller = new AbortController();
    const sort: SearchSort[] = [
      { field: "timestamp", order: "asc" },
      { field: "gl2_message_id", order: "asc" },
    ];

    const poll = async (): Promise<void> => {
      const from = newest === undefined ? since : Math.max(since, newest - TAIL_OVERLAP_MS);
      for (let offset = 0; ;) {
        const res = await client.search(query, {
          from: new Date(from),
          to: new Date(Date.now() + 60_000),
          limit: 1000,
          offset,
          sort,
          ...(streams === undefined ? {} : { streams }),
          signal: controller.signal,
        });
        for (const m of res.messages) {
          if (stopped) return;
          if (m.id !== "" && seen.has(m.id)) continue;
          const t = m.timestamp?.getTime() ?? since;
          seen.set(m.id, t);
          if (newest === undefined || t > newest) newest = t;
          try {
            onRecord(logRecordFromMessage(m.fields));
          } catch {
            // a failing callback must not stop the tail
          }
        }
        offset += res.messages.length;
        if (res.messages.length === 0 || offset >= res.total) break;
      }
      // Forget ids that can no longer appear in a window.
      if (newest !== undefined) {
        const cutoff = newest - 2 * TAIL_OVERLAP_MS;
        for (const [id, t] of seen) if (t < cutoff) seen.delete(id);
      }
    };
    const stop = (): void => {
      stopped = true;
      clearTimeout(timer);
      controller.abort();
    };
    const tick = async (): Promise<void> => {
      if (client.closed) {
        stop();
        return;
      }
      try {
        await poll();
      } catch (error) {
        if (!stopped) opts.onError?.(error);
      }
      if (!stopped) {
        timer = setTimeout(() => void tick(), intervalMs);
        timer.unref();
      }
    };
    void tick();
    return { stop };
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
