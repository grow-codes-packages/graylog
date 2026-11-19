# @grow-codes/graylog

TypeScript SDK for [Graylog Open](https://grow-codes-packages.github.io/graylog/) by Grow Codes:
GELF transports (UDP chunked, TCP null-framed with TLS and reconnect, HTTP bulk with gzip), an
optional OTLP/gRPC logs exporter, search, and REST admin (inputs, streams, index sets). Node.js
22.12 or newer, ESM and CommonJS, full type definitions.

```sh
npm install @grow-codes/graylog
```

```ts
import { GraylogClient } from "@grow-codes/graylog";

// Reads GRAYLOG_URL, GRAYLOG_API_TOKEN (or GRAYLOG_USER/GRAYLOG_PASSWORD), GRAYLOG_GELF_HOST,
// GRAYLOG_GELF_PORT, GRAYLOG_GELF_PROTOCOL (udp/tcp/http) and their GROW_GRAYLOG_* overrides.
const client = GraylogClient.fromEnv();
try {
  console.log(await client.health()); // { healthy: true, status: "ok", details: { lb_status: "ALIVE" } }

  const logs = client.logClient({ resource: { "service.name": "checkout" } }); // GELF, batched
  logs.logger("api").warn("payment slow", { order_id: 42, password: "redacted before sending" });
  await logs.flush();

  const record = await client.logQueryClient().waitForLog("order_id:42");
  console.log(record.body, record.severityText, record.resource["service.name"]);
} finally {
  await client.close(); // flushes every log client
}
```

Every error is a `GraylogError` subclass with a canonical `code` (`NOT_FOUND`,
`AUTHENTICATION`, `RATE_LIMITED`, …), `httpStatus`, `requestId` and `retryable`. Credentials
never appear in messages, logs, hook data or `toString()` output.

Test helpers (in-memory fakes and the conformance runner) live in
`@grow-codes/graylog/testing`.

Documentation: https://grow-codes-packages.github.io/graylog/ · Licence: Apache-2.0.
Graylog is a trademark of Graylog, Inc.; this package is not affiliated with or endorsed by Graylog, Inc.
