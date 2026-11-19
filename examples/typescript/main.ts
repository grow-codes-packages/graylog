// Graylog Open TypeScript SDK tour: configuration from the environment, health, version, admin
// (inputs, streams, index sets), sending logs through GELF and reading them back with search.
//
//   (cd ../../typescript && npm install && npm run build)   # or use the published package
//   npm install
//   GRAYLOG_URL=http://127.0.0.1:9000 GRAYLOG_API_TOKEN=... GRAYLOG_GELF_HOST=127.0.0.1 npm start

import { randomBytes } from "node:crypto";
import { GraylogClient, GraylogError, Severity } from "@grow-codes/graylog";

const client = GraylogClient.fromEnv({
  // Warnings only; the default logger is silent.
  logger: { debug() {}, info() {}, warn: console.warn, error: console.error },
});
console.log(`config: ${client.config}`); // credentials print as [REDACTED]

try {
  const health = await client.health(); // never throws for an unreachable service
  console.log("health:", health);
  if (!health.healthy) process.exit(1);
  console.log(
    `ping: ${(await client.ping({ signal: AbortSignal.timeout(10_000) })).toFixed(1)} ms`,
  );
  console.log("server version:", await client.serverVersion());

  // Admin: make sure a GELF input exists for the configured protocol and port.
  const protocol = client.config.gelfProtocol;
  const input = await client.ensureGelfInput(
    protocol,
    client.config.gelfPortFor(protocol),
  );
  console.log(
    `GELF ${protocol} input ${input.id} (${input.created ? "created" : "existing"})`,
  );
  const indexSets = await client.listIndexSets();
  console.log(
    "index sets:",
    indexSets.map((s) => `${s.title}${s.isDefault ? " (default)" : ""}`),
  );
  console.log(
    "streams:",
    (await client.listStreams()).streams.map((s) => s.title),
  );

  // Send logs through GELF (batched, redacted) and find them again.
  const run = randomBytes(4).toString("hex");
  const logs = client.logClient({
    resource: { "service.name": "example", "deployment.environment": "dev" },
  });
  const log = logs.logger("example", { run });
  log.info(`hello from the example ${run}`, {
    user_id: 42,
    password: "never-sent",
  });
  log.error(`something failed ${run}`, { attempt: 3 });
  await logs.flush();

  const query = client.logQueryClient();
  const found = await query.waitForLog(`run:${run} AND level:3`, {
    timeoutMs: 20_000,
  });
  console.log(
    "found:",
    found.severity === Severity.Error,
    found.body,
    found.attributes,
  );
  const page = await client.search(`run:${run}`, {
    range: 300,
    fields: ["message", "source"],
  });
  console.log(`search: ${page.total} messages`);
  const first = page.messages[0];
  if (first !== undefined) {
    const message = await client.getMessage(first.index, first.id);
    console.log("getMessage:", message.fields.message);
  }
} catch (err) {
  if (err instanceof GraylogError) {
    // Canonical code + HTTP status; the message never contains credentials.
    console.error(`${err.code}: ${err.message}`, {
      httpStatus: err.httpStatus,
    });
    process.exitCode = 1;
  } else {
    throw err;
  }
} finally {
  await client.close(); // flushes every log client
}
