# Functions

The Graylog Open API of this SDK. Every function exists in all five languages with the same
behaviour, defaults and error codes; each page shows every function with an example per language.
Names follow the language convention (`listInputs` in TypeScript and Java, `list_inputs` in Rust
and Python, `ListInputs` in Go with `ctx` first).

| Page | What |
| - | - |
| [Client and status](functions/client.md) | `fromEnv`, `health`, `ping`, `serverVersion`, `systemInfo`, `listFields`, `close` |
| [Admin: inputs, streams, index sets](functions/admin.md) | `listInputs`, `getInput`, `listInputTypes`, `getInputState`, `createInput`, `ensureGelfInput`, `deleteInput`, `listStreams`, `getStream`, `createStream`, `resumeStream`, `deleteStream`, `listIndexSets` |
| [Search](functions/search.md) | `search`, `searchRelative`, `getMessage`, `logRecordFromMessage` |
| [GELF messages and transports](functions/gelf.md) | `GelfMessage`, `GelfUdpTransport`, `GelfTcpTransport`, `GelfHttpTransport`, `gelfTransport`, `GelfLogExporter` |
| [Log client, OTLP and log query](functions/logging.md) | `logClient` (GELF UDP/TCP/HTTP, OTLP/gRPC), `OtlpGrpcLogExporter`, `logQueryClient` (`search`, `tail`, `listStreams`, `listLabels`, `waitForLog`) |

## Overview

| Function | Graylog API | Integration test |
| - | - | - |
| `health()` | `GET /api/system/lbstatus` (unauthenticated) | `core.health` + every suite |
| `ping()` | `GET /api/system` | `core.health` |
| `serverVersion()` / `systemInfo()` | `GET /api/system` | every suite |
| `listFields()` | `GET /api/system/fields` | suite `listLabels` |
| `listInputs()` / `getInput(id)` | `GET /api/system/inputs[/{id}]` | suite `inputs` |
| `listInputTypes()` | `GET /api/system/inputs/types` | suite `inputs` |
| `getInputState(id)` | `GET /api/system/inputstates/{id}` | suite `inputs` |
| `createInput(type, config)` | `POST /api/system/inputs` | suite `inputs` |
| `ensureGelfInput(protocol, port)` | list + create + wait until `RUNNING` | suite `inputs` (reuse, create, busy port → `CONFLICT`) |
| `deleteInput(id)` | `DELETE /api/system/inputs/{id}` | suite `inputs` |
| `listStreams()` / `getStream(id)` | `GET /api/streams/paginated`, `GET /api/streams/{id}` | suite `streams` |
| `createStream(opts)` | `POST /api/streams` (+ `POST /api/streams/{id}/resume`) | suite `streams` |
| `resumeStream(id)` / `deleteStream(id)` | `POST /api/streams/{id}/resume`, `DELETE /api/streams/{id}` | suite `streams` |
| `listIndexSets()` | `GET /api/system/indices/index_sets` | suite `streams` |
| `search(query, opts)` / `searchRelative(query, seconds)` | `POST /api/views/search/sync` | suite `search` + conformance `logging.roundtrip` |
| `getMessage(index, id)` | `GET /api/messages/{index}/{id}` | suite `search` |
| GELF UDP / TCP / HTTP transports | GELF inputs (UDP 12201, TCP 12201, HTTP 12202 in the fixture) | suite `transports` (UDP with retry-on-search) |
| `logClient({protocol})` | GELF or OTLP/gRPC (4317) | conformance `logging.*` + suite `log clients` |
| `logQueryClient()` | views search, polling tail | conformance `logging.roundtrip` + suite `tail` |

Functions the container cannot serve (unit tests only) are listed in
[Compatibility](compatibility.md#functions-the-service-cannot-serve).

## Service configuration

See [Configuration](configuration.md#graylog-settings) for every setting and environment variable
(REST URL and credentials, GELF host/port/protocol, GELF HTTP URL, GELF TLS, OTLP endpoint,
`X-Requested-By`).
