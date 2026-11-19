// Integration tests against the real Graylog Open stack (docker/compose.yml): every public function
// of the client is called at least once with a round-trip assertion.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, before, test } from "node:test";
import {
  GELF_INPUT_TYPES,
  GelfHttpTransport,
  GelfLevel,
  GelfMessage,
  GelfTcpTransport,
  GelfUdpTransport,
  GraylogClient,
  GraylogError,
  Severity,
  type GraylogMessage,
  type LogRecord,
} from "@grow-codes/graylog";
import { loadBootstrapEnv, runId } from "./env.ts";

const run = `ts${randomBytes(5).toString("hex")}`;
const clients: GraylogClient[] = [];

function graylog(): GraylogClient {
  const c = GraylogClient.fromEnv({ retry: { maxRetries: 2, initialBackoffMs: 50 } });
  clients.push(c);
  return c;
}

function env(name: string): string {
  const v = process.env[name];
  assert.ok(v, `${name} must be set (bootstrap env)`);
  return v;
}

/** Polls `client.search` until `minCount` messages match (ingest takes 1–2 s). */
async function searchUntil(
  client: GraylogClient,
  query: string,
  minCount = 1,
  timeoutMs = 30_000,
): Promise<GraylogMessage[]> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const res = await client.search(query, { range: 600, limit: 100 });
    if (res.messages.length >= minCount) return res.messages;
    if (Date.now() > deadline) {
      assert.fail(`search ${JSON.stringify(query)}: ${res.messages.length} < ${minCount} messages`);
    }
    await new Promise((r) => setTimeout(r, 500));
  }
}

before(() => {
  loadBootstrapEnv();
  assert.ok(
    process.env.GROW_GRAYLOG_URL ?? process.env.GRAYLOG_URL,
    "GROW_GRAYLOG_URL must be set",
  );
  console.log(`run ${runId}/${run}`);
});

after(async () => {
  await Promise.all(clients.map((c) => c.close()));
});

test("health reports a healthy service", async () => {
  const health = await graylog().health();
  assert.equal(health.healthy, true, JSON.stringify(health));
  assert.equal(health.status, "ok");
  assert.equal(health.details.lb_status, "ALIVE");
});

test("ping succeeds with the token and with user/password", async () => {
  const latency = await graylog().ping();
  assert.ok(latency >= 0);
  const passwordOnly = new GraylogClient({
    url: graylog().config.url,
    username: env("GRAYLOG_USER"),
    password: env("GRAYLOG_PASSWORD"),
  });
  clients.push(passwordOnly);
  assert.ok((await passwordOnly.ping()) >= 0);
});

test("ping with a wrong token raises AUTHENTICATION and never leaks it", async () => {
  const wrong = "wrong-token-for-integration";
  const client = new GraylogClient({ url: graylog().config.url, apiToken: wrong });
  clients.push(client);
  await assert.rejects(client.ping(), (err: unknown) => {
    assert.ok(err instanceof GraylogError);
    assert.equal(err.code, "AUTHENTICATION");
    assert.equal(err.httpStatus, 401);
    assert.ok(!err.message.includes(wrong));
    return true;
  });
});

test("serverVersion and systemInfo report the same version", async () => {
  const client = graylog();
  const version = await client.serverVersion();
  assert.match(version, /^\d+\.\d+\.\d+/);
  const info = await client.systemInfo();
  assert.equal(info.version, version);
  assert.equal(info.isProcessing, true);
  assert.ok(info.nodeId !== "");
  console.log(`graylog ${version}`);
});

test("inputs: listInputTypes, listInputs, getInput, getInputState", async () => {
  const client = graylog();
  const types = await client.listInputTypes();
  assert.equal(types[GELF_INPUT_TYPES.tcp], "GELF TCP");
  const inputs = await client.listInputs();
  const tcpId = env("GRAYLOG_INPUT_ID_GELF_TCP");
  const tcp = inputs.find((i) => i.id === tcpId);
  assert.ok(tcp, "bootstrap TCP input listed");
  assert.equal(tcp.type, GELF_INPUT_TYPES.tcp);
  assert.equal(tcp.port, 12201);
  const one = await client.getInput(tcpId);
  assert.equal(one.title, tcp.title);
  const state = await client.getInputState(tcpId);
  assert.equal(state.state, "RUNNING");
  assert.equal(state.input?.id, tcpId);
});

test("inputs: createInput → getInput → deleteInput → NOT_FOUND", async () => {
  const client = graylog();
  const port = 20_000 + Math.floor(Math.random() * 10_000);
  const id = await client.createInput(
    GELF_INPUT_TYPES.udp,
    { bind_address: "0.0.0.0", port, recv_buffer_size: 262_144, number_worker_threads: 1 },
    { title: `grow-sdk ts ${run}` },
  );
  assert.match(id, /^[0-9a-f]{24}$/);
  const input = await client.getInput(id);
  assert.equal(input.title, `grow-sdk ts ${run}`);
  assert.equal(input.port, port);
  await client.deleteInput(id);
  await assert.rejects(client.getInput(id), (e: unknown) => {
    assert.ok(e instanceof GraylogError);
    assert.equal(e.code, "NOT_FOUND");
    return true;
  });
  await assert.rejects(client.createInput("org.example.NoSuchInput", {}), {
    code: "NOT_FOUND",
  });
});

test("inputs: ensureGelfInput reuses the bootstrap input and creates a new one", async () => {
  const client = graylog();
  const existing = await client.ensureGelfInput("tcp", 12201);
  assert.equal(existing.created, false);
  assert.equal(existing.id, env("GRAYLOG_INPUT_ID_GELF_TCP"));
  const port = 30_000 + Math.floor(Math.random() * 10_000);
  const fresh = await client.ensureGelfInput("http", port, { title: `grow-sdk ts http ${run}` });
  try {
    assert.equal(fresh.created, true);
    assert.equal(fresh.port, port);
    assert.equal((await client.getInputState(fresh.id)).state, "RUNNING");
    const again = await client.ensureGelfInput("http", port);
    assert.equal(again.created, false);
    assert.equal(again.id, fresh.id);
  } finally {
    await client.deleteInput(fresh.id);
  }
});

test("streams + index sets: listIndexSets, createStream, getStream, listStreams, resumeStream, deleteStream; search by stream", async () => {
  const client = graylog();
  const sets = await client.listIndexSets();
  const def = sets.find((s) => s.isDefault);
  assert.ok(def, "default index set");
  assert.equal(def.id, env("GRAYLOG_DEFAULT_INDEX_SET_ID"));
  const title = `grow-sdk ts ${run}`;
  const id = await client.createStream({
    title,
    description: "TypeScript integration",
    rules: [{ field: "stream_marker", type: 1, value: run, inverted: false, description: "" }],
  });
  try {
    const stream = await client.getStream(id);
    assert.equal(stream.title, title);
    assert.equal(stream.disabled, false, "createStream resumes the stream");
    assert.equal(stream.indexSetId, def.id);
    assert.equal(stream.rules[0]?.value, run);
    const page = await client.listStreams({ query: run });
    assert.ok(page.streams.some((s) => s.id === id));
    assert.ok(page.total >= 1);
    const paused = await client.createStream({
      title: `${title} paused`,
      start: false,
      indexSetId: def.id,
    });
    try {
      assert.equal((await client.getStream(paused)).disabled, true);
      await client.resumeStream(paused);
      assert.equal((await client.getStream(paused)).disabled, false);
    } finally {
      await client.deleteStream(paused);
    }

    // a message matching the rule is routed into the stream
    const transport = client.gelfTransport("tcp");
    await transport.send([
      new GelfMessage({ host: "it", shortMessage: `routed ${run}` }).setField("stream_marker", run),
      new GelfMessage({ host: "it", shortMessage: `not routed ${run}` }),
    ]);
    await transport.close();
    await searchUntil(client, `"${run}"`, 2);
    const inStream = await client.search(`"${run}"`, { range: 600, streams: [id] });
    assert.deepEqual(
      inStream.messages.map((m) => m.fields.message),
      [`routed ${run}`],
    );
  } finally {
    await client.deleteStream(id);
  }
  await assert.rejects(client.getStream(id), { code: "NOT_FOUND" });
});

test("GELF TCP transport + search + searchRelative + getMessage + listFields", async () => {
  const client = graylog();
  const tcp = new GelfTcpTransport({
    host: env("GRAYLOG_GELF_HOST"),
    port: Number(env("GRAYLOG_GELF_TCP_PORT")),
  });
  const ts = new Date(Date.now() - 1000);
  const result = await tcp.send([
    new GelfMessage({
      host: "ts-tcp",
      shortMessage: `tcp one ${run}`,
      fullMessage: "line1\nline2",
      timestamp: ts,
      level: GelfLevel.Warning,
      fields: { marker: `tcp${run}`, seq: 1, ok: true, nested: { a: 1 } },
    }),
    new GelfMessage({
      host: "ts-tcp",
      shortMessage: `tcp two ${run}`,
      fields: { marker: `tcp${run}`, seq: 2 },
    }),
  ]);
  assert.deepEqual(result, { sent: 2, rejected: 0 });
  assert.equal(tcp.connections, 1);
  await tcp.close();

  const hits = await searchUntil(client, `marker:tcp${run}`, 2);
  const one = hits.find((m) => m.fields.seq === 1);
  assert.ok(one);
  assert.equal(one.fields.source, "ts-tcp");
  assert.equal(one.fields.full_message, "line1\nline2");
  assert.equal(one.fields.level, 4);
  assert.equal(one.fields.ok, "true");
  assert.equal(one.fields.nested, '{"a":1}');
  assert.equal(one.timestamp?.getTime(), Math.round(ts.getTime()));

  const sorted = await client.search(`marker:tcp${run}`, {
    from: new Date(Date.now() - 600_000),
    to: new Date(Date.now() + 60_000),
    sort: { field: "seq", order: "asc" },
    fields: ["message", "seq"],
    limit: 1,
  });
  assert.equal(sorted.total, 2);
  assert.equal(sorted.messages[0]?.fields.seq, 1);
  assert.equal(sorted.nextOffset, 1);
  assert.equal(sorted.messages[0]?.fields.source, undefined, "fields projection");
  const page2 = await client.search(`marker:tcp${run}`, {
    keyword: "last ten minutes",
    sort: { field: "seq", order: "asc" },
    limit: 1,
    offset: 1,
  });
  assert.equal(page2.messages[0]?.fields.seq, 2);
  assert.equal(page2.nextOffset, undefined);

  const relative = await client.searchRelative(`marker:tcp${run}`, 600);
  assert.equal(relative.total, 2);
  assert.ok(relative.from !== null && relative.to !== null);

  const message = await client.getMessage(one.index, one.id);
  assert.equal(message.id, one.id);
  assert.equal(message.fields.message, `tcp one ${run}`);
  await assert.rejects(client.getMessage(one.index, "00000000-0000-0000-0000-000000000000"), {
    code: "NOT_FOUND",
  });

  await assert.rejects(client.search("marker:(("), { code: "VALIDATION" });
  const fields = await client.listFields();
  assert.ok(fields.includes("marker") && fields.includes("seq"), fields.join(","));
});

test("GELF UDP transport (plain, zlib and a chunked gzip message), retried on search", async () => {
  const client = graylog();
  const host = env("GRAYLOG_GELF_HOST");
  const port = Number(env("GRAYLOG_GELF_UDP_PORT"));
  const big = randomBytes(9000).toString("base64"); // ~12 KB: several chunks even gzipped
  const deadline = Date.now() + 45_000;
  for (let attempt = 1; ; attempt++) {
    for (const compression of ["none", "zlib", "gzip"] as const) {
      const udp = new GelfUdpTransport({ host, port, compression });
      const res = await udp.send([
        new GelfMessage({
          host: "ts-udp",
          shortMessage: `udp ${compression} ${run}`,
          fields: { marker: `udp${run}` },
        }),
      ]);
      assert.equal(res.sent, 1);
      await udp.close();
    }
    const chunked = new GelfUdpTransport({ host, port, chunkSize: 1420 });
    await chunked.send([
      new GelfMessage({
        host: "ts-udp",
        shortMessage: `udp chunked ${run}`,
        fullMessage: big,
        fields: { marker: `udp${run}` },
      }),
    ]);
    await chunked.close();
    await new Promise((r) => setTimeout(r, 2500));
    const res = await client.search(`marker:udp${run}`, { range: 600 });
    const bodies = new Set(res.messages.map((m) => m.fields.message));
    const want = ["none", "zlib", "gzip", "chunked"].map((c) => `udp ${c} ${run}`);
    if (want.every((w) => bodies.has(w))) {
      const chunkedHit = res.messages.find((m) => m.fields.message === `udp chunked ${run}`);
      assert.equal(chunkedHit?.fields.full_message, big);
      return;
    }
    if (Date.now() > deadline)
      assert.fail(`UDP: got ${[...bodies].join(", ")} after ${attempt} attempts`);
  }
});

test("GELF HTTP transport: bulk gzip and single requests", async () => {
  const client = graylog();
  const url = env("GRAYLOG_GELF_HTTP_URL");
  const bulk = new GelfHttpTransport({ url });
  const msgs = [1, 2, 3].map(
    (i) =>
      new GelfMessage({
        host: "ts-http",
        shortMessage: `http bulk ${i} ${run}`,
        fields: { marker: `http${run}`, i },
      }),
  );
  assert.deepEqual(await bulk.send(msgs), { sent: 3, rejected: 0 });
  await bulk.close();
  // one request per message on a kept-alive connection (Graylog drops messages without a
  // trailing newline on reused connections; the transport terminates every message)
  const single = new GelfHttpTransport({ url, gzip: false, bulk: false });
  const singles = ["a", "b", "c", "d"].map(
    (x) =>
      new GelfMessage({
        host: "ts-http",
        shortMessage: `http single ${x} ${run}`,
        fields: { marker: `http${run}` },
      }),
  );
  assert.deepEqual(await single.send(singles), { sent: 4, rejected: 0 });
  assert.deepEqual(await single.send(singles.slice(0, 1)), { sent: 1, rejected: 0 });
  await single.close();
  const hits = await searchUntil(client, `marker:http${run}`, 8);
  assert.equal(hits.length, 8);
});

for (const protocol of ["tcp", "udp", "http", "otlp"] as const) {
  test(`logClient (${protocol}) → logQueryClient search / waitForLog / cursor`, async () => {
    const client = graylog();
    const service = `sdk-ts-${protocol}-${run}`;
    const logs = client.logClient({
      protocol,
      resource: {
        "service.name": service,
        "deployment.environment": "test",
        "host.name": "ts-host",
      },
      batch: { flushIntervalMs: 100 },
    });
    const query = client.logQueryClient();
    const log = logs.logger("integration", { component: "it" });
    const t0 = Date.now();
    log.warn(`hello ${protocol} ${run}`, {
      request_id: `r-${run}`,
      password: `hunter2-${run}`,
      id: "x1",
      n: 7,
    });
    logs.send({
      timestamp: new Date(t0 + 5),
      message: `traced ${protocol} ${run}`,
      severity: Severity.Error,
      traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
      spanId: "00f067aa0ba902b7",
      traceFlags: 1,
    });
    await logs.flush();
    assert.deepEqual(logs.stats(), { queued: 0, sent: 2, dropped: 0, failed: 0, retries: 0 });

    const lookFor =
      protocol === "otlp"
        ? `otel_resource_attributes_service_name:"${service}"`
        : `service_name:"${service}"`;
    const read = async (): Promise<LogRecord[]> => {
      const deadline = Date.now() + (protocol === "udp" ? 45_000 : 30_000);
      for (;;) {
        const res = await query.search(lookFor, { order: "asc", limit: 10 });
        if (res.records.length >= 2 || Date.now() > deadline) return res.records;
        if (protocol === "udp" && res.records.length === 0 && Date.now() - t0 > 10_000) {
          // UDP is best effort: send once more
          logs.send({
            message: `hello ${protocol} ${run}`,
            severity: Severity.Warn,
            attributes: { request_id: `r-${run}`, id: "x1", n: 7 },
          });
          await logs.flush();
        }
        await new Promise((r) => setTimeout(r, 500));
      }
    };
    const records = await read();
    const hello = records.find((r) => r.body === `hello ${protocol} ${run}`);
    const traced = records.find((r) => r.body === `traced ${protocol} ${run}`);
    assert.ok(hello, JSON.stringify(records));
    assert.ok(traced, JSON.stringify(records));
    assert.equal(hello.severity, Severity.Warn);
    assert.equal(hello.attributes.request_id, `r-${run}`);
    assert.equal(hello.attributes.n, 7);
    assert.equal(hello.resource["service.name"], service);
    if (protocol !== "otlp") {
      assert.equal(hello.attributes.id, "x1", "id attribute round-trips through _attr_id");
      assert.equal(hello.resource["host.name"], "ts-host");
      assert.equal(hello.resource["deployment.environment"], "test");
    }
    assert.ok(!JSON.stringify(records).includes(`hunter2-${run}`), "password must be redacted");
    assert.equal(traced.severity, Severity.Error);
    assert.equal(traced.traceId, "4bf92f3577b34da6a3ce929d0e0e4736");
    assert.equal(traced.spanId, "00f067aa0ba902b7");

    const waited = await query.waitForLog(lookFor, {
      predicate: (r) => r.traceId !== undefined,
      timeoutMs: 10_000,
      intervalMs: 250,
    });
    assert.equal(waited.body, `traced ${protocol} ${run}`);

    if (protocol !== "udp") {
      const page1 = await query.search(lookFor, { limit: 1, order: "asc" });
      assert.equal(page1.records[0]?.body, `hello ${protocol} ${run}`);
      assert.equal(page1.nextCursor, "1");
      assert.equal(page1.total, 2);
      const page2 = await query.search(lookFor, {
        limit: 1,
        order: "asc",
        cursor: page1.nextCursor,
      });
      assert.equal(page2.records[0]?.body, `traced ${protocol} ${run}`);
      assert.equal(page2.nextCursor, undefined);
    }
    await logs.close();
  });
}

test("logQueryClient: tail, listStreams, listLabels", async () => {
  const client = graylog();
  const query = client.logQueryClient();
  const logs = client.logClient({ protocol: "tcp", batch: { flushIntervalMs: 100 } });
  const got: LogRecord[] = [];
  const errors: unknown[] = [];
  const handle = query.tail(`tailmark:${run}`, (r) => got.push(r), {
    intervalMs: 500,
    onError: (e) => errors.push(e),
  });
  await new Promise((r) => setTimeout(r, 300));
  logs.send({ message: `live ${run}`, attributes: { tailmark: run, n: 1 } });
  await logs.flush();
  const deadline = Date.now() + 20_000;
  while (got.length === 0 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 200));
  handle.stop();
  assert.deepEqual(errors, []);
  assert.equal(got[0]?.body, `live ${run}`);
  assert.equal(got[0]?.attributes.n, 1);

  const streams = await query.listStreams();
  assert.ok(streams.includes("Default Stream"), streams.join(","));
  const labels = await query.listLabels();
  assert.ok(labels.includes("tailmark"), "new field listed");
});
