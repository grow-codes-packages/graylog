// Shared conformance scenarios (conformance/scenarios) against the real Graylog with the core and
// logging factories. Capabilities: core "version"; logging "query", "tail", "labels", "streams"
// (nothing skipped). The logging target sends GELF over TCP (the default protocol).

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { GraylogClient } from "@grow-codes/graylog";
import { formatReport, runConformance } from "@grow-codes/graylog/testing";
import { loadBootstrapEnv, scenariosDir } from "./env.ts";

const clients: GraylogClient[] = [];

function graylog(): GraylogClient {
  const c = GraylogClient.fromEnv({ retry: { maxRetries: 2, initialBackoffMs: 50 } });
  clients.push(c);
  return c;
}

before(() => {
  loadBootstrapEnv();
});

after(async () => {
  await Promise.all(clients.map((c) => c.close()));
});

for (const protocol of ["tcp", "http"] as const) {
  test(`conformance: core + logging (GELF ${protocol})`, async () => {
    const report = await runConformance({
      scenariosDir,
      categories: protocol === "tcp" ? ["core", "logging"] : ["logging"],
      factories: {
        core: () => graylog(),
        logging: (ctx) => {
          const client = graylog();
          return {
            client: client.logClient({
              protocol,
              batch: { flushIntervalMs: 200, ...(ctx.batchOptions ?? {}) },
              resource: { "service.name": `sdk-ts-conformance-${protocol}` },
            }),
            query: client.logQueryClient(),
          };
        },
      },
      capabilities: { core: ["version"], logging: ["query", "tail", "labels", "streams"] },
    });
    console.log(formatReport(report));
    assert.equal(report.failed, 0, formatReport(report));
    assert.equal(report.skipped, 0, formatReport(report));
    assert.ok(report.passed >= 3);
  });
}
