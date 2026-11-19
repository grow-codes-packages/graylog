// Mock Graylog REST server driven by the recorded fixtures (test/fixtures, real 7.0.16 responses).

import { readFileSync } from "node:fs";
import { GraylogClient, type GraylogConfigOptions } from "../../src/index.js";
import { type MockResponse, type MockServer, type RecordedRequest, startServer } from "./server.js";

interface Fixture {
  request: { method?: string; path?: string; body?: unknown };
  response: { status: number; headers: Record<string, string>; body: unknown };
}

/** Loads `test/fixtures/<name>.json`. */
export function loadFixture(name: string): Fixture {
  return JSON.parse(
    readFileSync(new URL(`../fixtures/${name}.json`, import.meta.url), "utf8"),
  ) as Fixture;
}

/** The recorded response of a fixture as a mock response. */
export function fixture(name: string): MockResponse {
  const { response } = loadFixture(name);
  const headers = { ...response.headers };
  const body = response.body;
  if (body === null || body === undefined) return { status: response.status, headers, body: "" };
  if (typeof body === "string") return { status: response.status, headers, body };
  return { status: response.status, headers: { ...headers, "content-type": "application/json" }, body: body as object };
}

/** Route key: `"GET /api/system"` (path without query) → response or handler. */
export type Routes = Record<string, MockResponse | ((req: RecordedRequest) => MockResponse)>;

/** Starts a mock Graylog answering `routes` (404 ApiError otherwise). */
export async function startGraylog(routes: Routes): Promise<MockServer> {
  return startServer((req) => {
    const key = `${req.method} ${req.url.split("?")[0] ?? ""}`;
    const route = routes[key];
    if (route === undefined) {
      return { status: 404, body: { type: "ApiError", message: `no route ${key}` } };
    }
    return typeof route === "function" ? route(req) : route;
  });
}

/** Client options with fast retries and a token. */
export const fastOptions: GraylogConfigOptions = {
  apiToken: "test-api-token-value",
  retry: { maxRetries: 1, initialBackoffMs: 1 },
};

/** A client for a mock server. */
export function clientFor(server: MockServer, options: GraylogConfigOptions = {}): GraylogClient {
  return new GraylogClient({ ...fastOptions, url: server.url, ...options });
}

/** Parsed JSON body of a recorded request. */
export function jsonBody(req: RecordedRequest | undefined): Record<string, unknown> {
  return JSON.parse(req?.body ?? "{}") as Record<string, unknown>;
}
