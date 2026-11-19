import { inspect } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import {
  ConfigError,
  DEFAULT_REQUESTED_BY,
  GraylogClient,
  GraylogConfig,
  GraylogError,
  PACKAGE_KEY,
  REDACTED,
  RetryPolicy,
  Secret,
  VENDOR_ENV,
  bareHost,
  parseGelfProtocol,
  urlHost,
} from "../src/index.js";
import { clientFor, fixture, startGraylog } from "./helpers/graylog.js";
import { type MockServer, closedPort, startServer } from "./helpers/server.js";

const servers: MockServer[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

async function track(p: Promise<MockServer>): Promise<MockServer> {
  const s = await p;
  servers.push(s);
  return s;
}

const basic = (u: string, p: string): string =>
  `Basic ${Buffer.from(`${u}:${p}`).toString("base64")}`;

describe("GraylogConfig", () => {
  it("uses defaults and freezes", () => {
    const c = new GraylogConfig();
    expect(c.url).toBe("http://127.0.0.1:9000");
    expect(c.requestTimeoutMs).toBe(30_000);
    expect(c.retry).toBeInstanceOf(RetryPolicy);
    expect(c.apiToken).toBeUndefined();
    expect(c.gelfHost).toBe("127.0.0.1");
    expect(c.gelfProtocol).toBe("tcp");
    expect(c.gelfPort).toBeUndefined();
    expect(c.gelfPortFor()).toBe(12201);
    expect(c.gelfPortFor("udp")).toBe(12201);
    expect(c.gelfPortFor("http")).toBe(12202);
    expect(c.gelfHttpEndpoint()).toBe("http://127.0.0.1:12202/gelf");
    expect(c.otlpGrpcEndpoint()).toBe("http://127.0.0.1:4317");
    expect(c.gelfTls).toBe(false);
    expect(c.requestedBy).toBe(DEFAULT_REQUESTED_BY);
    expect(c.authorizationHeader()).toBeUndefined();
    expect(c.knownSecrets()).toEqual([]);
    expect(Object.isFrozen(c)).toBe(true);
    expect(GraylogConfig.from(c)).toBe(c);
    expect(GraylogConfig.from().url).toBe(c.url);
    expect(GraylogConfig.ENV_PREFIX).toBe(`GROW_${PACKAGE_KEY.toUpperCase()}_`);
  });

  it("keeps explicit settings and derives GELF endpoints", () => {
    const hooks = {};
    const logger = { debug() {}, info() {}, warn() {}, error() {} };
    const c = new GraylogConfig({
      url: "https://graylog.example:9443",
      proxy: "http://p:1",
      userAgentSuffix: "s",
      hooks,
      logger,
      apiToken: new Secret("abcd-token"),
      gelfPort: 5555,
      gelfProtocol: "http",
      gelfTls: true,
      requestedBy: "me",
    });
    expect(c.gelfHost).toBe("graylog.example");
    expect(c.gelfPortFor("udp")).toBe(5555);
    expect(c.gelfHttpEndpoint()).toBe("https://graylog.example:5555/gelf");
    expect(c.proxy).toBe("http://p:1");
    expect(c.userAgentSuffix).toBe("s");
    expect(c.hooks).toBe(hooks);
    expect(c.logger).toBe(logger);
    expect(c.requestedBy).toBe("me");
    const explicit = new GraylogConfig({
      gelfHost: "[::1]",
      gelfHttpUrl: "http://in:1/gelf",
      otlpEndpoint: "http://otel:4317",
    });
    expect(explicit.gelfHost).toBe("::1");
    expect(explicit.gelfHttpEndpoint()).toBe("http://in:1/gelf");
    expect(explicit.otlpGrpcEndpoint()).toBe("http://otel:4317");
    expect(new GraylogConfig({ gelfHost: "::1" }).otlpGrpcEndpoint()).toBe("http://[::1]:4317");
  });

  it("builds Basic auth: token wins over user/password", () => {
    const token = new GraylogConfig({ apiToken: "tok-1234", username: "u", password: "pw-12345" });
    expect(token.authorizationHeader()).toBe(basic("tok-1234", "token"));
    expect(token.knownSecrets()).toEqual(
      expect.arrayContaining(["tok-1234", "pw-12345", basic("tok-1234", "token").slice(6)]),
    );
    const pw = new GraylogConfig({ username: "admin", password: "pw-12345" });
    expect(pw.authorizationHeader()).toBe(basic("admin", "pw-12345"));
    expect(pw.knownSecrets()).toContain(basic("admin", "pw-12345").slice(6));
  });

  it("redacts credentials in toString, JSON and inspect", () => {
    const c = new GraylogConfig({
      apiToken: "super-secret-token",
      username: "admin",
      password: "super-secret-pw",
      gelfHttpUrl: "http://u:pass@in:1/gelf?token=abc",
      otlpEndpoint: "http://otel:4317",
    });
    for (const text of [c.toString(), JSON.stringify(c), inspect(c)]) {
      expect(text).not.toContain("super-secret");
      expect(text).toContain(REDACTED);
      expect(text).toContain("admin");
    }
    expect(JSON.stringify(new GraylogConfig())).toContain('"apiToken":null');
  });

  it("validates", () => {
    const bad: [Record<string, unknown>, string][] = [
      [{ apiToken: "  " }, "apiToken must not be blank"],
      [{ username: "u" }, "username and password"],
      [{ password: "p" }, "username and password"],
      [{ gelfPort: 0 }, "gelfPort"],
      [{ gelfPort: 1.5 }, "gelfPort"],
      [{ gelfProtocol: "smtp" }, "gelfProtocol"],
      [{ gelfHttpUrl: "ftp://x" }, "gelfHttpUrl"],
      [{ gelfHttpUrl: "::" }, "gelfHttpUrl"],
      [{ otlpEndpoint: "grpc://x" }, "otlpEndpoint"],
      [{ requestedBy: " " }, "requestedBy"],
      [{ url: "nope" }, "url"],
    ];
    for (const [options, message] of bad) {
      expect(() => new GraylogConfig(options), message).toThrow(ConfigError);
      expect(() => new GraylogConfig(options)).toThrow(message);
    }
  });

  it("with() copies and overrides", () => {
    const c = new GraylogConfig({
      apiToken: "t-1234",
      username: "u",
      password: "p",
      gelfPort: 1,
      gelfHttpUrl: "http://a/gelf",
      otlpEndpoint: "http://o:1",
      proxy: "http://p:1",
      userAgentSuffix: "x",
      hooks: {},
      logger: { debug() {}, info() {}, warn() {}, error() {} },
    });
    const d = c.with({ gelfProtocol: "udp" });
    expect(d.gelfProtocol).toBe("udp");
    expect(d.apiToken?.reveal()).toBe("t-1234");
    expect(d.gelfHttpUrl).toBe("http://a/gelf");
    expect(new GraylogConfig().with({ url: "http://x:1" }).gelfHost).toBe("127.0.0.1");
  });

  it("fromEnv: GROW_ > vendor > platform aliases > defaults; overrides win", () => {
    const env = {
      GRAYLOG_URL: "http://vendor:9000",
      GRAYLOG_API_TOKEN: "vendor-token",
      GRAYLOG_USER: "admin",
      GRAYLOG_PASSWORD: "vendor-pw",
      GRAYLOG_HOST: "platform-host",
      GRAYLOG_PORT: "1111",
      GRAYLOG_TRANSPORT: "UDP",
      GRAYLOG_GELF_HTTP_URL: "http://vendor:12202/gelf",
      GRAYLOG_OTLP_GRPC_ENDPOINT: "http://vendor:4317",
      GROW_GRAYLOG_GELF_TLS: "yes",
    };
    const c = GraylogConfig.fromEnv({}, env);
    expect(c.url).toBe("http://vendor:9000");
    expect(c.apiToken?.reveal()).toBe("vendor-token");
    expect(c.username).toBe("admin");
    expect(c.password?.reveal()).toBe("vendor-pw");
    expect(c.gelfHost).toBe("platform-host");
    expect(c.gelfPort).toBe(1111);
    expect(c.gelfProtocol).toBe("udp");
    expect(c.gelfHttpUrl).toBe("http://vendor:12202/gelf");
    expect(c.otlpEndpoint).toBe("http://vendor:4317");
    expect(c.gelfTls).toBe(true);

    const layered = GraylogConfig.fromEnv(
      { gelfPort: 3333 },
      {
        ...env,
        GRAYLOG_GELF_HOST: "vendor-gelf",
        GRAYLOG_GELF_PORT: "2222",
        GRAYLOG_GELF_PROTOCOL: "http",
        GROW_GRAYLOG_URL: "http://grow:9000",
        GROW_GRAYLOG_API_TOKEN: "grow-token",
        GROW_GRAYLOG_GELF_PROTOCOL: "tcp",
        GROW_GRAYLOG_OTLP_ENDPOINT: "http://grow:4317",
        GROW_GRAYLOG_GELF_HTTP_URL: "http://grow/gelf",
        GROW_GRAYLOG_USER: "grow-user",
        GROW_GRAYLOG_PASSWORD: "grow-pw",
        GROW_GRAYLOG_GELF_HOST: "grow-gelf",
      },
    );
    expect(layered.url).toBe("http://grow:9000");
    expect(layered.apiToken?.reveal()).toBe("grow-token");
    expect(layered.gelfHost).toBe("grow-gelf");
    expect(layered.gelfPort).toBe(3333);
    expect(layered.gelfProtocol).toBe("tcp");
    expect(layered.otlpEndpoint).toBe("http://grow:4317");
    expect(layered.username).toBe("grow-user");

    expect(GraylogConfig.fromEnv({}, { GRAYLOG_GELF_PORT: "2222" }).gelfPort).toBe(2222);
    expect(GraylogConfig.fromEnv({}, {}).url).toBe(GraylogConfig.DEFAULT_URL);
    expect(VENDOR_ENV.gelfProtocol).toEqual(["GRAYLOG_GELF_PROTOCOL", "GRAYLOG_TRANSPORT"]);
  });

  it("fromEnv names the bad variable but never its value", () => {
    expect(() => GraylogConfig.fromEnv({}, { GRAYLOG_TRANSPORT: "carrier-pigeon" })).toThrow(
      /GRAYLOG_TRANSPORT: expected udp, tcp or http/,
    );
    try {
      GraylogConfig.fromEnv({}, { GROW_GRAYLOG_GELF_PORT: "abc" });
    } catch (err) {
      expect((err as Error).message).toContain("GROW_GRAYLOG_GELF_PORT");
      expect((err as Error).message).not.toContain("abc");
    }
  });

  it("helpers", () => {
    expect(parseGelfProtocol(" HTTP ")).toBe("http");
    expect(parseGelfProtocol("x")).toBeUndefined();
    expect(bareHost("[::1]")).toBe("::1");
    expect(bareHost("h")).toBe("h");
    expect(urlHost("::1")).toBe("[::1]");
    expect(urlHost("[::1]")).toBe("[::1]");
    expect(urlHost("h")).toBe("h");
  });
});

describe("GraylogClient surface", () => {
  it("health: ALIVE → ok, sends Accept text/plain", async () => {
    const s = await track(startGraylog({ "GET /api/system/lbstatus": fixture("health.ok") }));
    const client = clientFor(s);
    expect(await client.health()).toEqual({
      healthy: true,
      status: "ok",
      details: { lb_status: "ALIVE" },
    });
    expect(s.requests[0]?.headers.accept).toBe("text/plain");
    await client.close();
  });

  it("health: THROTTLED → degraded, DEAD → unhealthy, other words, errors, unreachable", async () => {
    const answers = [
      { status: 429, body: "THROTTLED" },
      { status: 503, body: "DEAD" },
      { status: 200, body: "STARTING" },
      { status: 500, body: "<html>oops</html>", headers: { "content-type": "text/html" } },
    ];
    const s = await track(startServer((_r, i) => answers[i] ?? { status: 404 }));
    const client = clientFor(s, { retry: { maxRetries: 0 } });
    expect(await client.health()).toMatchObject({ healthy: false, status: "degraded" });
    expect(await client.health()).toMatchObject({
      healthy: false,
      status: "unhealthy",
      details: { lb_status: "DEAD" },
    });
    expect(await client.health()).toMatchObject({
      healthy: false,
      details: { lb_status: "STARTING" },
    });
    expect(await client.health()).toMatchObject({
      healthy: false,
      status: "unhealthy",
      details: { httpStatus: "500" },
    });
    const down = new GraylogClient({
      url: `http://127.0.0.1:${await closedPort()}`,
      retry: { maxRetries: 0 },
    });
    expect(await down.health()).toMatchObject({ healthy: false, status: "unreachable" });
    const ac = new AbortController();
    ac.abort();
    await expect(client.health({ signal: ac.signal })).rejects.toMatchObject({ code: "CANCELLED" });
  });

  it("ping, serverVersion, systemInfo with auth + X-Requested-By + User-Agent", async () => {
    const s = await track(startGraylog({ "GET /api/system": fixture("ping.ok_token") }));
    const client = clientFor(s);
    expect(await client.ping()).toBeGreaterThanOrEqual(0);
    expect(await client.serverVersion()).toBe("7.0.16+58e0f6e");
    const info = await client.systemInfo();
    expect(info).toMatchObject({
      facility: "graylog-server",
      codename: "Noir",
      version: "7.0.16+58e0f6e",
      lbStatus: "alive",
      timezone: "Etc/UTC",
      isLeader: true,
      isProcessing: true,
    });
    expect(info.startedAt).toEqual(new Date("2026-11-18T20:27:42.909Z"));
    const req = s.requests[0];
    expect(req?.headers.authorization).toBe(basic("test-api-token-value", "token"));
    expect(req?.headers["x-requested-by"]).toBe(DEFAULT_REQUESTED_BY);
    expect(req?.headers["user-agent"]).toMatch(
      /^grow-codes-graylog\/\d+\.\d+\.\d+ \(typescript\)$/,
    );
    await client.close();
    await client.close();
    await expect(client.ping()).rejects.toMatchObject({ code: "CONFIG" });
  });

  it("serverVersion: UNSUPPORTED when no version is reported", async () => {
    const s = await track(startGraylog({ "GET /api/system": { status: 200, body: {} } }));
    await expect(clientFor(s).serverVersion()).rejects.toMatchObject({ code: "UNSUPPORTED" });
  });

  it("maps 401 (empty body) to AUTHENTICATION without leaking the token", async () => {
    const s = await track(startGraylog({ "GET /api/system": fixture("ping.unauthorized") }));
    const client = clientFor(s, { apiToken: "leaky-token-1234" });
    const err = await client.ping().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(GraylogError);
    expect(err).toMatchObject({ code: "AUTHENTICATION", httpStatus: 401, retryable: false });
    expect((err as Error).message).not.toContain("leaky-token-1234");
  });

  it("maps HTML 500 to UNAVAILABLE and JSON 404 ApiError to NOT_FOUND with the vendor message", async () => {
    const s = await track(
      startGraylog({
        "GET /api/system": {
          status: 500,
          headers: { "content-type": "text/html" },
          body: "<html><body>MongoTimeoutException</body></html>",
        },
        "GET /api/system/inputs/x": fixture("getInput.not_found"),
      }),
    );
    const client = clientFor(s, { retry: { maxRetries: 0 } });
    const err = (await client.systemInfo().catch((e: unknown) => e)) as GraylogError;
    expect(err.code).toBe("UNAVAILABLE");
    expect(err.message).not.toContain("<html>");
    const nf = (await client.getInput("x").catch((e: unknown) => e)) as GraylogError;
    expect(nf.code).toBe("NOT_FOUND");
    expect(nf.message).toMatch(/not found! \(HTTP 404\)$/);
  });

  it("rejects non-object JSON responses", async () => {
    const s = await track(
      startGraylog({
        "GET /api/system": {
          status: 200,
          body: "[1]",
          headers: { "content-type": "application/json" },
        },
      }),
    );
    await expect(clientFor(s).systemInfo()).rejects.toMatchObject({ code: "UNAVAILABLE" });
  });

  it("fromEnv builds a client", async () => {
    const saved = { ...process.env };
    process.env.GROW_GRAYLOG_URL = "http://env-host:9000";
    try {
      const c = GraylogClient.fromEnv({ apiToken: "x-1234" });
      expect(c.config.url).toBe("http://env-host:9000");
      expect(c.transport.userAgent).toContain("grow-codes-graylog/");
      await c.close();
    } finally {
      process.env = saved;
    }
  });
});
