import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CancelledError,
  DEFAULT_TAIL_INTERVAL_MS,
  TAIL_OVERLAP_MS,
  GraylogLogQueryClient,
  Severity,
  type LogRecord,
} from "../src/index.js";
import { clientFor, fixture, jsonBody, loadFixture, startGraylog } from "./helpers/graylog.js";
import type { MockServer, RecordedRequest } from "./helpers/server.js";

const servers: MockServer[] = [];
afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

async function graylog(routes: Parameters<typeof startGraylog>[0]): Promise<MockServer> {
  const s = await startGraylog(routes);
  servers.push(s);
  return s;
}

type Q = {
  query: { query_string: string };
  timerange: Record<string, unknown>;
  filter?: { filters: { id: string }[] };
  search_types: Record<string, unknown>[];
};
function queryOf(req: RecordedRequest | undefined): Q {
  return (jsonBody(req).queries as Q[])[0] as Q;
}

describe("search", () => {
  it("default: relative 300 s, limit 100, timestamp desc; decodes hits", async () => {
    const s = await graylog({
      "POST /api/views/search/sync": fixture("search.absolute_sorted_fields"),
    });
    const client = clientFor(s);
    const res = await client.search("marker:x");
    const q = queryOf(s.requests[0]);
    expect(q.query).toEqual({ type: "elasticsearch", query_string: "marker:x" });
    expect(q.timerange).toEqual({ type: "relative", range: 300 });
    expect(q.filter).toBeUndefined();
    expect(q.search_types[0]).toEqual({
      id: "st1",
      type: "messages",
      limit: 100,
      offset: 0,
      sort: [{ field: "timestamp", order: "DESC" }],
    });
    expect(s.requests[0]?.headers["x-requested-by"]).toBeTruthy();
    expect(res.total).toBe(3);
    expect(res.messages).toHaveLength(3);
    expect(res.messages[0]).toMatchObject({
      id: "99c65856-e38e-11f1-8dde-020650dd320d",
      index: "graylog_0",
      fields: { seq: 0 },
    });
    expect(res.messages[0]?.timestamp).toEqual(new Date("2026-11-18T20:28:22.938Z"));
    expect(res.from).toEqual(new Date("2026-11-18T20:28:15.935Z"));
    expect(res.to).toBeInstanceOf(Date);
    expect(res.nextOffset).toBeUndefined();
  });

  it("absolute range, fields, sort list, streams, offset → nextOffset", async () => {
    const body = loadFixture("search.desc_limit_offset").response.body as object;
    const s = await graylog({ "POST /api/views/search/sync": { status: 200, body } });
    const client = clientFor(s);
    const from = new Date("2026-11-18T20:00:00.000Z");
    const to = new Date("2026-11-18T21:00:00.000Z");
    const res = await client.search("", {
      from,
      to,
      fields: ["message"],
      sort: [{ field: "seq", order: "asc" }, { field: "timestamp" }],
      streams: ["s1", "s2"],
      limit: 1,
      offset: 1,
    });
    const q = queryOf(s.requests[0]);
    expect(q.query.query_string).toBe("*");
    expect(q.timerange).toEqual({
      type: "absolute",
      from: from.toISOString(),
      to: to.toISOString(),
    });
    expect(q.filter).toEqual({
      type: "or",
      filters: [
        { type: "stream", id: "s1" },
        { type: "stream", id: "s2" },
      ],
    });
    expect(q.search_types[0]).toMatchObject({
      limit: 1,
      offset: 1,
      fields: ["message"],
      sort: [
        { field: "seq", order: "ASC" },
        { field: "timestamp", order: "DESC" },
      ],
    });
    expect(res.total).toBe(3);
    expect(res.messages).toHaveLength(1);
    expect(res.nextOffset).toBe(2);
  });

  it("from-only / to-only absolute ranges, keyword, searchRelative", async () => {
    const s = await graylog({ "POST /api/views/search/sync": fixture("search.keyword_range") });
    const client = clientFor(s);
    const to = new Date("2026-11-18T21:00:00.000Z");
    await client.search("x", { to });
    expect(queryOf(s.requests[0]).timerange.from).toBe("2026-11-18T20:55:00.000Z");
    await client.search("x", { from: new Date(Date.now() - 1000) });
    expect(queryOf(s.requests[1]).timerange.type).toBe("absolute");
    await client.search("x", { keyword: "last five minutes", sort: { field: "seq" } });
    expect(queryOf(s.requests[2]).timerange).toEqual({
      type: "keyword",
      keyword: "last five minutes",
    });
    expect(queryOf(s.requests[2]).search_types[0]?.sort).toEqual([{ field: "seq", order: "DESC" }]);
    await client.searchRelative("x", 60, { limit: 5 });
    expect(queryOf(s.requests[3]).timerange).toEqual({ type: "relative", range: 60 });
  });

  it("validates options client side", async () => {
    const s = await graylog({});
    const client = clientFor(s);
    const now = new Date();
    const cases = [
      { range: 10, keyword: "k" },
      { range: 10, from: now },
      { from: new Date(now.getTime() + 1000), to: now },
      { from: new Date("nope") },
      { keyword: " " },
      { range: 0 },
      { range: 1.5 },
      { limit: 0 },
      { limit: 10_001 },
      { offset: -1 },
    ];
    for (const options of cases) {
      await expect(client.search("x", options), JSON.stringify(options)).rejects.toMatchObject({
        code: "VALIDATION",
      });
    }
    expect(s.requests).toHaveLength(0);
  });

  it("HTTP 200 with errors → VALIDATION; 400 RequestError; 401", async () => {
    const s = await graylog({ "POST /api/views/search/sync": fixture("search.invalid_query") });
    await expect(clientFor(s).search("marker:((")).rejects.toMatchObject({
      code: "VALIDATION",
      message: expect.stringContaining("all shards failed") as unknown,
    });
    const flagged = await graylog({
      "POST /api/views/search/sync": {
        status: 200,
        body: { execution: { completed_exceptionally: true } },
      },
    });
    await expect(clientFor(flagged).search("x")).rejects.toThrow("search: query failed");
    const bad = await graylog({ "POST /api/views/search/sync": fixture("search.bad_request") });
    await expect(clientFor(bad).search("x")).rejects.toMatchObject({
      code: "VALIDATION",
      httpStatus: 400,
    });
    const unauth = await graylog({ "POST /api/views/search/sync": fixture("search.unauthorized") });
    await expect(clientFor(unauth).search("x")).rejects.toMatchObject({ code: "AUTHENTICATION" });
  });

  it("empty and sparse responses", async () => {
    const s = await graylog({ "POST /api/views/search/sync": fixture("search.empty") });
    const res = await clientFor(s).search("nothing");
    expect(res.messages).toEqual([]);
    expect(res.total).toBe(0);
    const sparse = await graylog({
      "POST /api/views/search/sync": {
        status: 200,
        body: {
          results: {
            q1: {
              search_types: { st1: { messages: [{ message: { id: "legacy", timestamp: 5 } }] } },
            },
          },
        },
      },
    });
    const r = await clientFor(sparse).search("x");
    expect(r.total).toBe(1);
    expect(r.messages[0]).toMatchObject({ id: "legacy", index: "", timestamp: null });
    expect(r.from).toBeNull();
    const bare = await graylog({ "POST /api/views/search/sync": { status: 200, body: {} } });
    expect((await clientFor(bare).search("x")).messages).toEqual([]);
  });

  it("stream filter fixture decodes", async () => {
    const s = await graylog({ "POST /api/views/search/sync": fixture("search.stream_filter") });
    const res = await clientFor(s).search("x", { streams: ["6afe0a6607ba3acebff1894e"] });
    expect(res.messages.length).toBeGreaterThan(0);
  });
});

describe("getMessage and listFields", () => {
  it("getMessage encodes segments and decodes fields; 404", async () => {
    const s = await graylog({
      "GET /api/messages/graylog_0/99c65855-e38e-11f1-8dde-020650dd320d": fixture("getMessage.ok"),
      "GET /api/messages/graylog_0/a%2Fb": fixture("getMessage.not_found"),
    });
    const client = clientFor(s);
    const m = await client.getMessage("graylog_0", "99c65855-e38e-11f1-8dde-020650dd320d");
    expect(m).toMatchObject({
      id: "99c65855-e38e-11f1-8dde-020650dd320d",
      index: "graylog_0",
      fields: { marker: "growsdk179503370112643", transport: "http", bool_attr: "true" },
    });
    expect(m.timestamp).toEqual(new Date("2026-11-18T20:28:22.938Z"));
    await expect(client.getMessage("graylog_0", "a/b")).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    await expect(client.getMessage("", "x")).rejects.toMatchObject({ code: "VALIDATION" });
    const empty = await graylog({ "GET /api/messages/i/x": { status: 200, body: {} } });
    expect(await clientFor(empty).getMessage("i", "x")).toMatchObject({ id: "", fields: {} });
  });

  it("listFields sorts the names", async () => {
    const s = await graylog({ "GET /api/system/fields": fixture("listLabels.ok") });
    const fields = await clientFor(s).listFields();
    expect(fields).toContain("trace_id");
    expect([...fields].sort()).toEqual(fields);
    const none = await graylog({ "GET /api/system/fields": { status: 200, body: {} } });
    expect(await clientFor(none).listFields()).toEqual([]);
  });
});

describe("GraylogLogQueryClient", () => {
  it("search: absolute window, sort with tie-breaker, cursor, normalised records", async () => {
    const body = loadFixture("search.desc_limit_offset").response.body as object;
    const s = await graylog({ "POST /api/views/search/sync": { status: 200, body } });
    const client = clientFor(s);
    const query = client.logQueryClient({ streams: ["s1"] });
    const end = new Date("2026-11-18T21:00:00.000Z");
    const res = await query.search("marker:x", { end, limit: 1, cursor: "1", order: "asc" });
    const q = queryOf(s.requests[0]);
    expect(q.timerange).toEqual({
      type: "absolute",
      from: "2026-11-18T20:00:00.000Z",
      to: end.toISOString(),
    });
    expect(q.search_types[0]).toMatchObject({
      limit: 1,
      offset: 1,
      sort: [
        { field: "timestamp", order: "ASC" },
        { field: "gl2_message_id", order: "ASC" },
      ],
    });
    expect(q.filter?.filters).toEqual([{ type: "stream", id: "s1" }]);
    expect(res.total).toBe(3);
    expect(res.nextCursor).toBe("2");
    const record = res.records[0] as LogRecord;
    expect(record.severity).toBe(Severity.Info);
    expect(record.resource["host.name"]).toBe("grow-sdk-verify");
    await expect(query.search("x", { cursor: "abc" })).rejects.toMatchObject({
      code: "VALIDATION",
    });
    const defaults = await query.search("x", { start: new Date(0) });
    expect(defaults.records.length).toBe(1);
    expect(queryOf(s.requests[1]).search_types[0]).toMatchObject({ limit: 100, offset: 0 });
  });

  it("search without cursor on the last page has no nextCursor; OTLP hits", async () => {
    const otlp = loadFixture("otlpLogs.searched").response.body as {
      message: Record<string, unknown>;
    };
    const s = await graylog({
      "POST /api/views/search/sync": {
        status: 200,
        body: {
          results: {
            q1: { search_types: { st1: { total_results: 1, messages: [otlp.message] } } },
          },
        },
      },
    });
    const res = await clientFor(s).logQueryClient().search("x");
    expect(res.nextCursor).toBeUndefined();
    expect(res.records[0]).toMatchObject({
      body: "growsdkotlp179503370112643 hello from otlp",
      severity: Severity.Warn,
      traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
      spanId: "00f067aa0ba902b7",
      resource: { "service.name": "grow-sdk-verify", marker: "growsdkotlp179503370112643" },
      attributes: { attr_k: "v", app: "server" },
    });
  });

  it("rejects a non-positive window", async () => {
    const s = await graylog({});
    expect(() => new GraylogLogQueryClient(clientFor(s), { defaultWindowMs: 0 })).toThrow(
      "defaultWindowMs",
    );
  });

  it("listStreams pages through titles; listLabels; waitForLog", async () => {
    let calls = 0;
    const s = await graylog({
      "GET /api/streams/paginated": (req) => {
        calls++;
        const page = Number(new URL(`http://x${req.url}`).searchParams.get("page"));
        const elements =
          page === 1 ? [{ title: "A" }, { title: "B" }] : page === 2 ? [{ title: "C" }] : [];
        return { status: 200, body: { pagination: { total: 3, page, per_page: 100 }, elements } };
      },
      "GET /api/system/fields": fixture("listLabels.ok"),
      "POST /api/views/search/sync": fixture("search.absolute_sorted_fields"),
    });
    const query = clientFor(s).logQueryClient();
    expect(await query.listStreams()).toEqual(["A", "B", "C"]);
    expect(calls).toBe(2);
    expect(await query.listLabels()).toContain("span_id");
    const found = await query.waitForLog("x", { timeoutMs: 1000, intervalMs: 10 });
    expect(found.attributes.marker).toBe("growsdk179503370112643");

    const empty = await graylog({
      "GET /api/streams/paginated": {
        status: 200,
        body: { pagination: { total: 5 }, elements: [] },
      },
    });
    expect(await clientFor(empty).logQueryClient().listStreams()).toEqual([]);
  });

  it("tail polls every 2 s by default and honours intervalMs", async () => {
    const s = await graylog({
      "POST /api/views/search/sync": fixture("search.absolute_sorted_fields"),
    });
    const query = clientFor(s).logQueryClient();
    const spy = vi.spyOn(globalThis, "setTimeout");
    const handle = query.tail("x", () => undefined, { start: new Date(0) });
    const until = Date.now() + 3000;
    while (!spy.mock.calls.some((c) => c[1] === DEFAULT_TAIL_INTERVAL_MS) && Date.now() < until)
      await new Promise((r) => setImmediate(r));
    expect(spy.mock.calls.some((c) => c[1] === DEFAULT_TAIL_INTERVAL_MS)).toBe(true);
    handle.stop();
    handle.stop();
    const got: LogRecord[] = [];
    const fast = query.tail("x", (r) => got.push(r), { start: new Date(0), intervalMs: 10 });
    const first = s.requests.length;
    const deadline = Date.now() + 3000;
    while (s.requests.length < first + 3 && Date.now() < deadline)
      await new Promise((r) => setTimeout(r, 10));
    fast.stop();
    spy.mockRestore();
    // the same three hits come back on every poll: delivered once each (dedupe by id)
    expect(got.length).toBe(3);
    const q = queryOf(s.requests[s.requests.length - 1]);
    expect(q.search_types[0]).toMatchObject({ limit: 1000, offset: 0 });
    // after the first poll the window starts 10 s before the newest record seen
    const newest = new Date("2026-11-18T20:28:22.938Z").getTime();
    expect(new Date(q.timerange.from as string).getTime()).toBe(newest - TAIL_OVERLAP_MS);
  });

  it("tail pages, reports errors, survives failing callbacks and stops on close", async () => {
    let calls = 0;
    const page = loadFixture("search.absolute_sorted_fields").response.body as {
      results: { q1: { search_types: { st1: { messages: unknown[]; total_results: number } } } };
    };
    const s = await graylog({
      "POST /api/views/search/sync": (req) => {
        calls++;
        if (calls === 2) return { status: 500, body: { type: "ApiError", message: "boom" } };
        const body = JSON.parse(JSON.stringify(page)) as typeof page;
        const st = body.results.q1.search_types.st1;
        const offset = (queryOf(req).search_types[0] as { offset: number }).offset;
        st.total_results = 4;
        st.messages = offset === 0 ? st.messages.slice(0, 2) : st.messages.slice(2);
        if (offset !== 0) {
          const extra = JSON.parse(JSON.stringify(st.messages[0])) as {
            message: Record<string, unknown>;
          };
          extra.message._id = "";
          st.messages.push(extra);
        }
        return { status: 200, body };
      },
    });
    const client = clientFor(s, { retry: { maxRetries: 0 } });
    const query = client.logQueryClient({ streams: ["s1"] });
    const got: LogRecord[] = [];
    const errors: unknown[] = [];
    const handle = query.tail(
      "x",
      (r) => {
        got.push(r);
        throw new Error("callback failure");
      },
      { start: new Date(0), intervalMs: 5, onError: (e) => errors.push(e) },
    );
    const deadline = Date.now() + 3000;
    while ((errors.length === 0 || got.length < 4) && Date.now() < deadline)
      await new Promise((r) => setTimeout(r, 5));
    expect(got.length).toBeGreaterThanOrEqual(4);
    expect(errors.length).toBe(1);
    expect(queryOf(s.requests[0]).filter?.filters[0]?.id).toBe("s1");
    await client.close();
    const after = s.requests.length;
    await new Promise((r) => setTimeout(r, 40));
    expect(s.requests.length).toBeLessThanOrEqual(after + 1);
    handle.stop();
    expect(() => query.tail("x", () => undefined)).toThrow(CancelledError);
  });

  it("a closed client fails every call with CANCELLED", async () => {
    const s = await graylog({ "GET /api/system": fixture("ping.ok_token") });
    const client = clientFor(s);
    await client.close();
    expect(client.closed).toBe(true);
    await expect(client.ping()).rejects.toMatchObject({ code: "CANCELLED" });
    await expect(client.health()).rejects.toBeInstanceOf(CancelledError);
    await expect(client.listInputs()).rejects.toBeInstanceOf(CancelledError);
    expect(() => client.logClient()).toThrow(CancelledError);
    await client.close();
  });
});
