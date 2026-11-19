# Compatibility

## Runtimes

| Language | Supported | Tested in CI |
| - | - | - |
| TypeScript | Node.js ≥ 22.12, ESM and CommonJS | Node 22, 24 |
| Rust | MSRV 1.88, edition 2021, tokio | stable, 1.88 |
| Go | Go ≥ 1.26 | 1.26, 1.27 |
| Python | ≥ 3.10 (OTLP/gRPC needs the `otlp` extra) | 3.10, 3.13, 3.14 |
| Java | ≥ 17 (Java 17 bytecode) | Temurin 17, 21, 25 |

## Graylog Open versions

The integration suite runs against **`graylog/graylog:7.0`** (the tag pinned in the Grow Codes
stack catalog; it resolved to `7.0.16+58e0f6e` when this release was verified) with
`opensearchproject/opensearch:2.19.0` and MongoDB. `7.0` is a moving minor tag, so the suite
prints `serverVersion()` in its output. Other Graylog versions that expose the same REST API
(`/api/views/search/sync`, `/api/streams/paginated`, `/api/system/inputs`) and GELF 1.1 are
expected to work; report problems as an issue. Graylog Enterprise/Cloud features (Illuminate,
archives, the Data Node API) are not covered.

### Docker fixture

- `docker/compose.yml` starts Graylog, OpenSearch (security plugin off, 512 MiB heap) and MongoDB
  with health checks and no published ports. A one-shot bootstrap creates the inputs GELF UDP 12201,
  GELF TCP 12201 (NUL framing), GELF HTTP 12202 (bulk receiving) and OpenTelemetry gRPC 4317
  (insecure), an API token for `admin`, and writes them to `/bootstrap/env`.
- **MongoDB 7 instead of 8 on some kernels.** The catalog image is `mongo:8.2.3-noble`, but MongoDB
  8.x crashes on Linux kernels **6.19 to 7.0.13** (SERVER-121912, TCMalloc vs the rseq ABI): on the
  development host (kernel 7.0.0-22) `mongo:8.2.3-noble` segfaults about 30 s after start and newer
  8.0 patches refuse to start. On such hosts the fixture uses **`mongo:7.0.48-jammy`** (Graylog 7.0
  supports MongoDB 7.0 to 8.2). `make test-docker` picks it automatically
  (`docker/mongo-image.sh`); set `GRAYLOG_SDK_MONGO_IMAGE` to choose an image yourself. GitHub-hosted
  runners (kernel 6.x below 6.19) keep the catalog image.
- The host needs `vm.max_map_count >= 262144` for OpenSearch (the CI job sets it). One stack takes
  about 2.5 GiB of RAM and becomes healthy in 30–50 s.

## Functions the service cannot serve

Every public function is called against the real service in the Docker suite. The cases below
cannot be produced by the container; they are covered by unit tests against mock servers in every
language.

| Function / case | Languages | Reason |
| - | - | - |
| `health()` → `degraded` (`THROTTLED`, 429) and `unhealthy` (`DEAD`, 503) | all | needs a throttled or failing node; mocked text responses |
| `PERMISSION_DENIED` (403) | all | the fixture only has the admin user |
| GELF TCP over TLS, GELF HTTP over HTTPS, TCP reconnect after a broken connection | all | the fixture inputs are plain; tested with a local TLS server and generated test certificates |
| OTLP/gRPC over TLS, OTLP partial success, gRPC error statuses | all | the fixture OTLP input is insecure and accepts everything |
| UDP delivery guarantees | all | UDP is best-effort; the integration suite asserts UDP delivery with retry-on-search only |
| the 128-chunk ceiling and the exact GELF chunk header bytes | all | deterministic unit tests |
| `tail()` as a stream | all | Graylog Open has no streaming API; `tail` polls search (tested live) |

## Skipped conformance scenarios

| Scenario | Reason |
| - | - |
| — | none: `core.health`, `logging.batch`, `logging.redaction` and `logging.roundtrip` run in every language (over GELF TCP and HTTP) |

## Service behaviour the SDK handles

| Graylog behaviour | SDK |
| - | - |
| Every non-GET request needs `X-Requested-By` (400 otherwise) | always sent (`requestedBy`, default `grow-codes-graylog`) |
| `lbstatus` answers 406 to `Accept: application/json` | `health()` sends `Accept: text/plain` |
| 401 has an empty body; a 500 can be an HTML page (e.g. MongoDB down) | errors never assume JSON; the message is redacted and truncated |
| Search query errors are HTTP 200 with `errors[]` | `VALIDATION` with Graylog's description |
| An unknown input type is 404 | `NOT_FOUND` |
| A busy port: `createInput` succeeds, the input state becomes `FAILED` | `ensureGelfInput` waits for the state and raises `CONFLICT` (and deletes the input it created) |
| New streams start paused; creation needs the `{"entity": …}` envelope | `createStream` wraps the body and resumes the stream (unless `start` is false) |
| GELF HTTP answers 202 even for invalid JSON or a missing `short_message` | messages are validated client-side; a blank body is sent as `"-"` |
| Graylog 7.0.16 drops the first message of the 3rd and later GELF HTTP bulk requests on a reused connection unless every message ends with `\n` | every message ends with `\n`, also single-message bodies |
| GELF drops boolean and null fields, stores objects/arrays as JSON text, stores `_id` as `id` | booleans → `"true"`/`"false"`, nulls omitted, arrays/objects → compact JSON, `id` → `_attr_id` |
| Stored field names have `.` replaced by `_` (`service_name`) | search maps them back to `service.name`, `deployment.environment`, … |
| Messages become searchable 1–2 s after ingest | `waitForLog` polls; `tail` looks back 10 s and dedupes by message id |
| No OTLP/HTTP input in Graylog Open 7.0 | only OTLP/gRPC is offered |

## Language differences

The API is the same in every language; only the conventions differ (naming, durations, async
model). Known differences:

| Area | Difference |
| - | - |
| Log client / log query names | TypeScript and Java `logClient` / `logQueryClient`, Python `log_client` / `log_query_client`, Rust `new_log_client` / `log_query`, Go `NewLogClient` / `LogQuery` |
| Tail interval | default 2 s everywhere; an explicit interval is honoured. Rust treats an interval equal to the shared `TailOptions` default (1 s) as unset (→ 2 s), because that type has no "unset" marker; Java `tail(query, onRecord)` uses 2 s while `tail(query, onRecord, TailOptions.defaults())` uses the template's 1 s as an explicit interval |
| Tail errors | reported to `onError` in TypeScript, Python and Java, to the SDK logger in Rust and Go; polling continues in all |
| Null attributes | dropped from GELF in every language. In Java the shared logging model turns a `null` attribute value into `""` before it reaches the GELF mapping, so it arrives as an empty string |
| OTLP/gRPC | TypeScript (`node:http2`), Rust (reqwest HTTP/2) and Java (OkHttp) hand-encode the protobuf messages; Go uses `google.golang.org/grpc`; Python needs the optional extra `pip install "grow-graylog[otlp]"` (grpcio, also in `[all]`) |
| OTLP/gRPC and `insecureSkipVerify` | Python ignores `insecure_skip_verify` for OTLP/gRPC (grpcio has no such switch); use a CA bundle (`ca_cert_path`) instead. The other languages honour it |
| `GelfProtocol.OTLP` | `otlp` is valid only as a log client protocol, not as `gelfProtocol` in the configuration (`CONFIG`); in Rust `GelfProtocol::Otlp` is valid only in `LogOptions.protocol` |
| Closed client | every call (REST, `logClient`, `tail`) on a closed client fails with `CANCELLED` in all five languages |
| Async | TypeScript promises; Rust async with a `blocking` client; Go `ctx`; Python `GraylogClient` and `AsyncGraylogClient` (the async log client sends GELF from worker threads); Java sync methods plus `…Async` futures |

Java cannot change the process environment, so `loadEnv` sets **system properties** instead and
returns the names it set.
