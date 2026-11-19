import { afterEach, describe, expect, it } from "vitest";
import { GELF_INPUT_TYPES, GraylogError, OTLP_GRPC_INPUT_TYPE } from "../src/index.js";
import { decodeInput, decodeInputState, decodeStreamRule } from "../src/models.js";
import { clientFor, fixture, jsonBody, loadFixture, startGraylog } from "./helpers/graylog.js";
import type { MockServer } from "./helpers/server.js";

const servers: MockServer[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

async function graylog(routes: Parameters<typeof startGraylog>[0]): Promise<MockServer> {
  const s = await startGraylog(routes);
  servers.push(s);
  return s;
}

const RUNNING_ID = "6afe0a6607ba3acebff1891c";

describe("inputs", () => {
  it("listInputs decodes the recorded inputs", async () => {
    const s = await graylog({ "GET /api/system/inputs": fixture("listInputs.ok") });
    const inputs = await clientFor(s).listInputs();
    expect(inputs).toHaveLength(4);
    const tcp = inputs.find((i) => i.type === GELF_INPUT_TYPES.tcp);
    expect(tcp).toMatchObject({
      title: "grow-sdk GELF TCP",
      name: "GELF TCP",
      global: true,
      node: null,
      port: 12201,
      bindAddress: "0.0.0.0",
      creatorUserId: "admin",
    });
    expect(tcp?.createdAt).toBeInstanceOf(Date);
    expect(inputs.find((i) => i.type === OTLP_GRPC_INPUT_TYPE)?.attributes.bearer_token).toEqual({
      is_set: false,
    });
  });

  it("listInputs tolerates a body without inputs", async () => {
    const s = await graylog({ "GET /api/system/inputs": { status: 200, body: {} } });
    expect(await clientFor(s).listInputs()).toEqual([]);
  });

  it("getInput, getInputState, listInputTypes", async () => {
    const s = await graylog({
      "GET /api/system/inputs/6afe0a6607ba3acebff1891c": fixture("getInput.ok"),
      [`GET /api/system/inputstates/${RUNNING_ID}`]: fixture("getInputState.running"),
      "GET /api/system/inputs/types": fixture("listInputTypes.ok"),
    });
    const client = clientFor(s);
    const input = await client.getInput(RUNNING_ID);
    expect(input.id).toBe(RUNNING_ID);
    const state = await client.getInputState(RUNNING_ID);
    expect(state.state).toBe("RUNNING");
    expect(state.input?.port).toBe(12299);
    expect(state.startedAt).toBeInstanceOf(Date);
    const types = await client.listInputTypes();
    expect(types[GELF_INPUT_TYPES.udp]).toBe("GELF UDP");
    expect(types[OTLP_GRPC_INPUT_TYPE]).toBe("OpenTelemetry (gRPC)");
    await expect(client.getInput(" ")).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("listInputTypes tolerates a missing map", async () => {
    const s = await graylog({ "GET /api/system/inputs/types": { status: 200, body: {} } });
    expect(await clientFor(s).listInputTypes()).toEqual({});
  });

  it("createInput posts title/type/global/configuration with X-Requested-By", async () => {
    const s = await graylog({ "POST /api/system/inputs": fixture("createInput.created") });
    const client = clientFor(s);
    const id = await client.createInput(
      GELF_INPUT_TYPES.tcp,
      { port: 1 },
      { title: "t", node: "n1", global: false },
    );
    expect(id).toMatch(/^[0-9a-f]{24}$/);
    const req = s.requests[0];
    expect(req?.headers["x-requested-by"]).toBeTruthy();
    expect(jsonBody(req)).toEqual({
      title: "t",
      type: GELF_INPUT_TYPES.tcp,
      global: false,
      node: "n1",
      configuration: { port: 1 },
    });
    await client.createInput(GELF_INPUT_TYPES.udp, {});
    expect(jsonBody(s.requests[1]).title).toBe("GELFUDPInput (grow-codes)");
    expect(jsonBody(s.requests[1]).global).toBe(true);
    await expect(client.createInput("", {})).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("createInput maps unknown types (404) and CSRF 400", async () => {
    const s = await graylog({ "POST /api/system/inputs": fixture("createInput.bad_type") });
    await expect(clientFor(s).createInput("x.Y", {})).rejects.toMatchObject({
      code: "NOT_FOUND",
      message: expect.stringContaining("no such input type") as unknown,
    });
    const csrf = await graylog({
      "POST /api/system/inputs": fixture("createInput.missing_requested_by"),
    });
    await expect(clientFor(csrf).createInput("x.Y", {})).rejects.toMatchObject({
      code: "VALIDATION",
    });
    const noId = await graylog({ "POST /api/system/inputs": { status: 201, body: {} } });
    await expect(clientFor(noId).createInput("x.Y", {})).rejects.toThrow("response without id");
  });

  it("deleteInput: 204 and 404", async () => {
    const s = await graylog({
      "DELETE /api/system/inputs/a": fixture("deleteInput.deleted"),
      "DELETE /api/system/inputs/b": fixture("deleteInput.not_found"),
    });
    const client = clientFor(s);
    await client.deleteInput("a");
    await expect(client.deleteInput("b")).rejects.toMatchObject({ code: "NOT_FOUND" });
  });
});

describe("ensureGelfInput", () => {
  const listed = loadFixture("listInputs.ok").response.body as { inputs: unknown[] };

  it("reuses a matching input", async () => {
    const tcpId = "6afe0a5807ba3acebff188dd";
    const s = await graylog({
      "GET /api/system/inputs": { status: 200, body: listed as object },
      [`GET /api/system/inputstates/${tcpId}`]: {
        status: 200,
        body: { id: tcpId, state: "RUNNING" },
      },
    });
    const input = await clientFor(s).ensureGelfInput("tcp", 12201);
    expect(input).toMatchObject({ id: tcpId, created: false, port: 12201 });
    expect(s.requests.some((r) => r.method === "POST")).toBe(false);
  });

  it("creates a missing input with protocol defaults and waits for RUNNING", async () => {
    const newId = "aaaaaaaaaaaaaaaaaaaaaaaa";
    let created = false;
    let polls = 0;
    const s = await graylog({
      "GET /api/system/inputs": () => ({
        status: 200,
        body: {
          inputs: created
            ? [
                ...listed.inputs,
                { id: newId, title: "x", type: GELF_INPUT_TYPES.http, attributes: { port: 12345 } },
              ]
            : listed.inputs,
        },
      }),
      "POST /api/system/inputs": () => {
        created = true;
        return { status: 201, body: { id: newId } };
      },
      [`GET /api/system/inputstates/${newId}`]: () => {
        polls++;
        if (polls === 1) return { status: 404, body: { type: "ApiError", message: "x" } };
        if (polls === 2) return { status: 200, body: { id: newId, state: "STARTING" } };
        return { status: 200, body: { id: newId, state: "RUNNING" } };
      },
    });
    const input = await clientFor(s).ensureGelfInput("http", 12345, {
      intervalMs: 5,
      configuration: { enable_cors: false },
    });
    expect(input).toMatchObject({ id: newId, created: true });
    const body = jsonBody(s.requests.find((r) => r.method === "POST"));
    expect(body.title).toBe("grow-codes GELF HTTP 12345");
    expect(body.configuration).toMatchObject({
      port: 12345,
      bind_address: "0.0.0.0",
      enable_bulk_receiving: true,
      enable_cors: false,
    });
    expect(polls).toBe(3);
  });

  it("udp/tcp defaults, falls back to getInput when the new input is not listed", async () => {
    for (const protocol of ["udp", "tcp"] as const) {
      const newId = "bbbbbbbbbbbbbbbbbbbbbbbb";
      const s = await graylog({
        "GET /api/system/inputs": { status: 200, body: { inputs: [] } },
        "POST /api/system/inputs": { status: 201, body: { id: newId } },
        [`GET /api/system/inputs/${newId}`]: {
          status: 200,
          body: { id: newId, type: GELF_INPUT_TYPES[protocol] },
        },
        [`GET /api/system/inputstates/${newId}`]: {
          status: 200,
          body: { id: newId, state: "RUNNING" },
        },
      });
      const input = await clientFor(s).ensureGelfInput(protocol, 4000, {
        bindAddress: "127.0.0.1",
      });
      expect(input.created).toBe(true);
      const conf = jsonBody(s.requests.find((r) => r.method === "POST")).configuration as Record<
        string,
        unknown
      >;
      expect(conf.bind_address).toBe("127.0.0.1");
      if (protocol === "tcp") expect(conf.use_null_delimiter).toBe(true);
      else expect(conf.recv_buffer_size).toBe(262_144);
    }
  });

  it("FAILED input → CONFLICT and the created input is deleted", async () => {
    const newId = "cccccccccccccccccccccccc";
    const s = await graylog({
      "GET /api/system/inputs": { status: 200, body: { inputs: [] } },
      "POST /api/system/inputs": { status: 201, body: { id: newId } },
      [`GET /api/system/inputs/${newId}`]: { status: 200, body: { id: newId } },
      [`GET /api/system/inputstates/${newId}`]: fixture("getInputState.port_collision"),
      [`DELETE /api/system/inputs/${newId}`]: { status: 204 },
    });
    const err = (await clientFor(s)
      .ensureGelfInput("udp", 12201)
      .catch((e: unknown) => e)) as GraylogError;
    expect(err.code).toBe("CONFLICT");
    expect(err.message).toContain("failed to start");
    expect(s.requests.some((r) => r.method === "DELETE")).toBe(true);
  });

  it("FAILED existing input → CONFLICT without delete; timeout deletes a created input", async () => {
    const id = "dddddddddddddddddddddddd";
    const s = await graylog({
      "GET /api/system/inputs": {
        status: 200,
        body: { inputs: [{ id, type: GELF_INPUT_TYPES.udp, attributes: { port: 7 } }] },
      },
      [`GET /api/system/inputstates/${id}`]: { status: 200, body: { id, state: "FAILED" } },
    });
    await expect(clientFor(s).ensureGelfInput("udp", 7)).rejects.toMatchObject({
      code: "CONFLICT",
      message: expect.not.stringContaining(":  ") as unknown,
    });
    expect(s.requests.some((r) => r.method === "DELETE")).toBe(false);

    const slow = await graylog({
      "GET /api/system/inputs": { status: 200, body: { inputs: [] } },
      "POST /api/system/inputs": { status: 201, body: { id } },
      [`GET /api/system/inputs/${id}`]: { status: 200, body: { id } },
      [`GET /api/system/inputstates/${id}`]: { status: 200, body: { id, state: "STARTING" } },
      [`DELETE /api/system/inputs/${id}`]: { status: 204 },
    });
    await expect(
      clientFor(slow).ensureGelfInput("udp", 7, { timeoutMs: 50, intervalMs: 10 }),
    ).rejects.toMatchObject({ code: "TIMEOUT" });
    expect(slow.requests.some((r) => r.method === "DELETE")).toBe(true);
  });

  it("validates protocol and port", async () => {
    const s = await graylog({});
    const client = clientFor(s);
    // @ts-expect-error invalid protocol
    await expect(client.ensureGelfInput("smtp", 1)).rejects.toMatchObject({ code: "VALIDATION" });
    await expect(client.ensureGelfInput("udp", 0)).rejects.toMatchObject({ code: "VALIDATION" });
  });
});

describe("streams and index sets", () => {
  it("listStreams sends paging params and decodes", async () => {
    const s = await graylog({ "GET /api/streams/paginated": fixture("listStreams.ok") });
    const client = clientFor(s);
    const page = await client.listStreams({
      query: "Default",
      perPage: 10,
      page: 1,
      order: "desc",
      sort: "title",
    });
    expect(page.total).toBe(3);
    expect(page.page).toBe(1);
    expect(page.perPage).toBe(50);
    const def = page.streams.find((x) => x.isDefault);
    expect(def).toMatchObject({
      id: "000000000000000000000001",
      title: "Default Stream",
      matchingType: "AND",
      disabled: false,
    });
    const url = new URL(`http://x${s.requests[0]?.url ?? ""}`);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      page: "1",
      per_page: "10",
      sort: "title",
      order: "desc",
      query: "Default",
    });
    await client.listStreams();
    expect(s.requests[1]?.url).toBe(
      "/api/streams/paginated?page=1&per_page=50&sort=title&order=asc",
    );
    await expect(client.listStreams({ page: 0 })).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("listStreams tolerates missing pagination", async () => {
    const s = await graylog({ "GET /api/streams/paginated": { status: 200, body: { total: 0 } } });
    expect(await clientFor(s).listStreams({ page: 2 })).toEqual({
      streams: [],
      total: 0,
      page: 2,
      perPage: 50,
    });
  });

  it("createStream wraps the entity, uses the default index set and resumes", async () => {
    const s = await graylog({
      "GET /api/system/indices/index_sets": fixture("listIndexSets.ok"),
      "POST /api/streams": fixture("createStream.created"),
      "POST /api/streams/6afe0a6607ba3acebff1894e/resume": fixture("resumeStream.ok"),
    });
    const id = await clientFor(s).createStream({
      title: "t",
      rules: [{ field: "marker", type: 1, value: "x", inverted: false, description: "d" }],
    });
    expect(id).toBe("6afe0a6607ba3acebff1894e");
    expect(s.requests.map((r) => `${r.method} ${r.url.split("?")[0] ?? ""}`)).toEqual([
      "GET /api/system/indices/index_sets",
      "POST /api/streams",
      "POST /api/streams/6afe0a6607ba3acebff1894e/resume",
    ]);
    expect(jsonBody(s.requests[1])).toEqual({
      entity: {
        title: "t",
        description: "",
        index_set_id: "6afe0a4d07ba3acebff18718",
        matching_type: "AND",
        remove_matches_from_default_stream: false,
        rules: [{ field: "marker", type: 1, value: "x", inverted: false, description: "d" }],
      },
    });
  });

  it("createStream with start:false and explicit index set; errors", async () => {
    const s = await graylog({ "POST /api/streams": fixture("createStream.created") });
    const client = clientFor(s);
    await client.createStream({
      title: "t",
      indexSetId: "i",
      start: false,
      matchingType: "OR",
      removeMatchesFromDefaultStream: true,
      description: "d",
    });
    expect(s.requests).toHaveLength(1);
    expect((jsonBody(s.requests[0]).entity as Record<string, unknown>).matching_type).toBe("OR");
    await expect(client.createStream({ title: "" })).rejects.toMatchObject({ code: "VALIDATION" });

    const bad = await graylog({ "POST /api/streams": fixture("createStream.missing_index_set") });
    await expect(
      clientFor(bad).createStream({ title: "t", indexSetId: "x" }),
    ).rejects.toMatchObject({
      code: "VALIDATION",
      message: expect.stringContaining("Null indexSetId") as unknown,
    });
    const none = await graylog({
      "GET /api/system/indices/index_sets": { status: 200, body: { index_sets: [] } },
    });
    await expect(clientFor(none).createStream({ title: "t" })).rejects.toThrow("no index set");
    const noId = await graylog({ "POST /api/streams": { status: 201, body: {} } });
    await expect(clientFor(noId).createStream({ title: "t", indexSetId: "i" })).rejects.toThrow(
      "stream_id",
    );
    const nonDefault = await graylog({
      "GET /api/system/indices/index_sets": { status: 200, body: { index_sets: [{ id: "only" }] } },
      "POST /api/streams": { status: 201, body: { stream_id: "s" } },
    });
    await clientFor(nonDefault).createStream({ title: "t", start: false });
    expect((jsonBody(nonDefault.requests[1]).entity as Record<string, unknown>).index_set_id).toBe(
      "only",
    );
  });

  it("getStream, resumeStream, deleteStream", async () => {
    const s = await graylog({
      "GET /api/streams/6afe0a6607ba3acebff1894e": fixture("getStream.created_disabled"),
      "GET /api/streams/missing": fixture("getStream.not_found"),
      "POST /api/streams/x/resume": { status: 204 },
      "DELETE /api/streams/x": fixture("deleteStream.deleted"),
      "DELETE /api/streams/y": fixture("deleteStream.not_found"),
    });
    const client = clientFor(s);
    const stream = await client.getStream("6afe0a6607ba3acebff1894e");
    expect(stream.disabled).toBe(true);
    expect(stream.rules[0]).toMatchObject({ field: "marker", type: 1 });
    await expect(client.getStream("missing")).rejects.toMatchObject({ code: "NOT_FOUND" });
    await client.resumeStream("x");
    await client.deleteStream("x");
    await expect(client.deleteStream("y")).rejects.toMatchObject({ code: "NOT_FOUND" });
  });

  it("listIndexSets", async () => {
    const s = await graylog({ "GET /api/system/indices/index_sets": fixture("listIndexSets.ok") });
    const sets = await clientFor(s).listIndexSets();
    expect(sets).toHaveLength(3);
    expect(sets.filter((x) => x.isDefault)).toHaveLength(1);
    expect(sets[0]).toMatchObject({
      title: "Default index set",
      indexPrefix: "graylog",
      shards: 1,
      replicas: 0,
      writable: true,
    });
    expect(s.requests[0]?.url).toBe("/api/system/indices/index_sets?skip_stats=true");
    const empty = await graylog({
      "GET /api/system/indices/index_sets": { status: 200, body: {} },
    });
    expect(await clientFor(empty).listIndexSets()).toEqual([]);
  });
});

describe("model decoders", () => {
  it("are defensive about missing fields", () => {
    expect(decodeInput(null)).toMatchObject({
      id: "",
      port: null,
      bindAddress: null,
      createdAt: null,
      staticFields: {},
    });
    expect(decodeInput({ static_fields: { a: 1 }, created_at: "nope" })).toMatchObject({
      staticFields: { a: "1" },
      createdAt: null,
    });
    expect(decodeInputState({})).toMatchObject({
      state: "UNKNOWN",
      input: null,
      detailedMessage: null,
    });
    expect(decodeStreamRule({ id: "r", value: 5 })).toEqual({
      id: "r",
      field: "",
      type: 0,
      value: "5",
      inverted: false,
      description: "",
    });
    expect(decodeStreamRule({ value: null }).value).toBe("");
  });
});
