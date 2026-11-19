---
name: graylog-sdk
description: Add and use the Grow Codes SDK for Graylog Open (`graylog`) in TypeScript, Rust, Go, Python or Java projects. Use when code must ship logs to Graylog (GELF UDP/TCP/HTTP, OTLP/gRPC), search Graylog messages, tail logs, or manage Graylog inputs, streams and index sets - installing @grow-codes/graylog, the grow-graylog crate or PyPI package, the Go module github.com/grow-codes-packages/graylog/go or Maven codes.grow.packages:graylog, configuring it with GROW_GRAYLOG_* variables, handling GraylogError codes, testing with the bundled fakes, or running the Docker integration suite of this repository.
---

# Graylog Open SDK (Grow Codes)

One API for Graylog Open in five languages (categories: logging). Pick the package for the
project's language, configure it from the environment, and handle errors by their canonical code.

## 1. Add the package

| Language | Command | Import |
| - | - | - |
| TypeScript | `npm install @grow-codes/graylog` | `import { GraylogClient } from "@grow-codes/graylog"` |
| Rust | `cargo add grow-graylog` (add `tokio` with `macros,rt-multi-thread`) | `use grow_graylog::GraylogClient;` |
| Go | `go get github.com/grow-codes-packages/graylog/go` | `graylog "github.com/grow-codes-packages/graylog/go"` |
| Python | `pip install grow-graylog` (or `uv add grow-graylog`) | `from grow_graylog import GraylogClient` |
| Java | Maven `codes.grow.packages:graylog` (Gradle `implementation("codes.grow.packages:graylog:<version>")`) | `import codes.grow.packages.graylog.GraylogClient;` |

Check the latest version in the README badges before pinning one.

## 2. Configure

Prefer environment configuration so no credential is written into code:

```sh
export GROW_GRAYLOG_URL=https://graylog.example.internal   # REST API (port 9000)
export GROW_GRAYLOG_API_TOKEN=...        # from your secret store, never committed
export GROW_GRAYLOG_GELF_HOST=graylog.example.internal     # GELF input host
export GROW_GRAYLOG_GELF_PROTOCOL=tcp    # udp | tcp (default) | http
```

Precedence: explicit config value > `GROW_GRAYLOG_*` > vendor variables (`GRAYLOG_URL`,
`GRAYLOG_API_TOKEN` or `GRAYLOG_USER`/`GRAYLOG_PASSWORD`, `GRAYLOG_GELF_HOST`, `GRAYLOG_GELF_PORT`,
`GRAYLOG_GELF_PROTOCOL`, `GRAYLOG_GELF_HTTP_URL`, `GRAYLOG_OTLP_GRPC_ENDPOINT`) > Grow stack aliases
(`GRAYLOG_HOST`, `GRAYLOG_PORT`, `GRAYLOG_TRANSPORT`) > default. Also `GROW_GRAYLOG_USER`/`_PASSWORD`,
`GROW_GRAYLOG_GELF_PORT` (default 12201, 12202 for http), `GROW_GRAYLOG_GELF_HTTP_URL`,
`GROW_GRAYLOG_GELF_TLS`, `GROW_GRAYLOG_OTLP_ENDPOINT` (default `http://<gelf host>:4317`).
Other variables: `…_CONNECT_TIMEOUT`, `…_REQUEST_TIMEOUT`, `…_TOTAL_TIMEOUT` (`10s`, `1500`),
`…_MAX_RETRIES`, `…_CA_CERT`, `…_CLIENT_CERT`, `…_CLIENT_KEY`, `…_PROXY`. Environment proxies
(`HTTPS_PROXY`) are ignored unless `proxy` is set.

## 3. Use

Create one client per process and close it on shutdown (TypeScript `await client.close()`, Rust
`client.close().await`, Go `defer client.Close()`, Python `with …`/`close()`, Java
try-with-resources).

- `health()` never throws for an unhealthy service; check `healthy`.
- `ping()` verifies credentials (`AUTHENTICATION` error when they are wrong).
- All I/O is retried with jitter on 429/502/503/504 and connection errors; only idempotent calls
  are retried on 500.
- Errors carry `code` (`CONFIG`, `AUTHENTICATION`, `PERMISSION_DENIED`, `NOT_FOUND`, `CONFLICT`,
  `RATE_LIMITED`, `VALIDATION`, `UNAVAILABLE`, `TIMEOUT`, `UNSUPPORTED`, `CANCELLED`), `retryable`,
  `httpStatus` and `requestId`. Branch on the code, not on the message text. Go:
  `errors.Is(err, graylog.ErrNotFound)`.

### Logging

Create the log client once, send records with `send`/`sendBatch` or use the logger facade
(`logger("component").info("message", attrs)`) or the framework adapter for the language (pino or
winston, `tracing`/`log`, `slog`/zap, `logging`/structlog, Logback/Log4j2/JUL). Records are batched
and redacted; call `close()` on shutdown so the queue is flushed.

### Graylog functions

| Task | TypeScript (other languages: same names in their style) |
| - | - |
| Ship logs | `client.logClient({ protocol: "tcp" \| "udp" \| "http" \| "otlp", resource })` → `logger(name).info(msg, attrs)`, `flush()` |
| Find logs | `client.logQueryClient().search(query, { start, end, limit, cursor })`, `waitForLog(query, { timeoutMs })` |
| Follow logs | `logQueryClient().tail(query, onRecord)` — polls every 2 s (no streaming API) |
| Raw search | `client.search(query, { range \| from+to \| keyword, limit, offset, fields, sort, streams })`, `searchRelative(query, seconds)`, `getMessage(index, id)` |
| Inputs | `ensureGelfInput("tcp", 12201)` (reuse or create, wait RUNNING; busy port → `CONFLICT`), `listInputs`, `createInput(type, config)`, `deleteInput` |
| Streams | `createStream({ title, rules })` (resumed automatically), `listStreams`, `getStream`, `deleteStream`, `listIndexSets` |
| Raw GELF | `new GelfMessage({ host, shortMessage, level, fields })`, `client.gelfTransport("udp").send([msg])` |

Names: Rust `new_log_client` / `log_query` / `ensure_gelf_input`; Go `NewLogClient` / `LogQuery` /
`EnsureGelfInput(ctx, …)`; Python `log_client` / `log_query_client` / `ensure_gelf_input`; Java
`logClient(GraylogLogClientOptions…)` / `logQueryClient()`.

Queries are Lucene: `marker:abc`, `"exact phrase"`, `level:<=3`, `_exists_:trace_id`,
`service_name:checkout` (Graylog stores `.` in field names as `_`; search results map them back to
`service.name`). Messages are searchable 1–2 s after ingest, so tests use `waitForLog`.

Gotchas:

- GELF UDP is best-effort; prefer TCP or HTTP when delivery matters.
- OTLP needs Graylog's *OpenTelemetry (gRPC)* input; Python needs `pip install "grow-graylog[otlp]"`.
- Booleans are sent as `"true"`/`"false"`, nulls are dropped, nested values become JSON strings.
- Every call on a closed client fails with `CANCELLED`.

Full examples for every function in all five languages: `docs/functions/*.md`.

## 4. Test code that uses the SDK

Use the in-memory fakes from the testing module instead of a real Graylog Open in unit tests:
TypeScript `@grow-codes/graylog/testing`, Rust feature `testing`, Go package `testkit`, Python
`grow_graylog.testing`, Java `codes.grow.packages.graylog.testing`.

## 5. Work on this repository

Read `AGENTS.md` first. Short version: the five languages keep the same API; files with the
`Generated by sdk-kit` header are changed in sdk-kit, not here; `make lint coverage` must pass
(≥ 90 % lines and branches); `make test-docker LANGS="<lang>"` runs the integration suite against
`graylog/graylog:7.0` with OpenSearch and MongoDB (MongoDB 7 is picked automatically on kernels
6.19–7.0.13, see `docs/compatibility.md`).
