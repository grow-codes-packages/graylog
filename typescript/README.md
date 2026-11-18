# @grow-codes/graylog

TypeScript SDK for [Graylog Open](https://grow-codes-packages.github.io/graylog/) by Grow Codes.
Node.js 22.12 or newer, ESM and CommonJS, full type definitions.

```sh
npm install @grow-codes/graylog
```

```ts
import { GraylogClient } from "@grow-codes/graylog";

// Reads GROW_GRAYLOG_URL, GROW_GRAYLOG_TOKEN, timeouts, TLS and proxy settings.
const client = GraylogClient.fromEnv();
try {
  console.log(await client.health()); // { healthy: true, status: "ok", details: {} }
  console.log(`ping: ${(await client.ping()).toFixed(1)} ms`);
} finally {
  await client.close();
}
```

Every error is a `GraylogError` subclass with a canonical `code` (`NOT_FOUND`,
`AUTHENTICATION`, `RATE_LIMITED`, …), `httpStatus`, `requestId` and `retryable`. Credentials
never appear in messages, logs, hook data or `toString()` output.

Test helpers (in-memory fakes and the conformance runner) live in
`@grow-codes/graylog/testing`.

Documentation: https://grow-codes-packages.github.io/graylog/ · Licence: Apache-2.0.
Graylog Open is a trademark of Graylog, Inc.; this package is not affiliated with or endorsed by it.
