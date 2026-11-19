# Grow Codes SDK for Graylog Open

[![CI](https://github.com/grow-codes-packages/graylog/actions/workflows/ci.yml/badge.svg)](https://github.com/grow-codes-packages/graylog/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/grow-codes-packages/graylog?sort=semver)](https://github.com/grow-codes-packages/graylog/releases)
[![Docs](https://img.shields.io/badge/docs-grow--codes--packages.github.io-blue)](https://grow-codes-packages.github.io/graylog/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Grow Codes](https://img.shields.io/badge/Grow%20Codes-grow.codes-2ea44f)](https://grow.codes)

| Language | Package | Coverage |
| - | - | - |
| TypeScript | [![npm](https://img.shields.io/npm/v/@grow-codes/graylog)](https://www.npmjs.com/package/@grow-codes/graylog) | [![TypeScript coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/graylog/badges/coverage-typescript.json)](https://github.com/grow-codes-packages/graylog/actions/workflows/ci.yml) |
| Rust | [![crates.io](https://img.shields.io/crates/v/grow-graylog)](https://crates.io/crates/grow-graylog) [![docs.rs](https://img.shields.io/docsrs/grow-graylog)](https://docs.rs/grow-graylog) | [![Rust coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/graylog/badges/coverage-rust.json)](https://github.com/grow-codes-packages/graylog/actions/workflows/ci.yml) |
| Go | [![Go Reference](https://pkg.go.dev/badge/github.com/grow-codes-packages/graylog/go.svg)](https://pkg.go.dev/github.com/grow-codes-packages/graylog/go) | [![Go coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/graylog/badges/coverage-go.json)](https://github.com/grow-codes-packages/graylog/actions/workflows/ci.yml) |
| Python | [![PyPI](https://img.shields.io/pypi/v/grow-graylog)](https://pypi.org/project/grow-graylog/) | [![Python coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/graylog/badges/coverage-python.json)](https://github.com/grow-codes-packages/graylog/actions/workflows/ci.yml) |
| Java | [![Maven Central](https://img.shields.io/maven-central/v/codes.grow.packages/graylog)](https://central.sonatype.com/artifact/codes.grow.packages/graylog) | [![Java coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/graylog/badges/coverage-java.json)](https://github.com/grow-codes-packages/graylog/actions/workflows/ci.yml) |

Open-source client libraries for [Graylog Open](#trademarks-and-disclaimer) in **TypeScript, Rust, Go,
Python and Java** — one API, five idiomatic packages, tested against a real Graylog Open in Docker.

- **Ship logs** through GELF over UDP (gzip/zlib, chunking up to 128 chunks), TCP (NUL framing,
  TLS, reconnect) or HTTP (bulk, gzip), or through OTLP/gRPC to Graylog's OpenTelemetry input —
  batched, redacted, with a logger facade and adapters for the common logging frameworks of each
  language.
- **Read logs back** with Graylog's Views search (Lucene queries, time ranges, streams, field
  selection, paging), `getMessage`, a polling `tail` and `waitForLog` for tests; stored fields are
  normalized back into log records.
- **Administer** inputs (`ensureGelfInput` reuses or creates a GELF input and waits until it runs),
  streams and index sets.
- **Typed client** with timeouts, retries with jitter, `Retry-After`, cancellation and one error
  model (`GraylogError` with canonical codes) in every language; credentials are redacted in
  `toString`, logs, hooks and error messages.

## Contents

- [Supported service version](#supported-service-version)
- [Install](#install)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Function overview](#function-overview)
- [Testing with Docker](#testing-with-docker)
- [Compatibility](#compatibility)
- [Contributing](#contributing)
- [Security](#security)
- [Licence](#licence)
- [Trademarks and disclaimer](#trademarks-and-disclaimer)
- [About Grow Codes](#about-grow-codes)

## Supported service version

Tested in CI against **`graylog/graylog:7.0`** (the tag pinned in the Grow Codes stack catalog;
`7.0.16+58e0f6e` when this release was verified) with `opensearchproject/opensearch:2.19.0` and
MongoDB `8.2.3-noble` (`7.0.48-jammy` on Linux kernels 6.19–7.0.13, where MongoDB 8 crashes). The
SDK uses the REST API (`/api/...`, port 9000), GELF 1.1 inputs (UDP/TCP 12201, HTTP 12202 in the
fixture) and the OpenTelemetry (gRPC) input (4317). Other Graylog versions with the same REST API
usually work; see [Compatibility](#compatibility) and [docs/compatibility.md](docs/compatibility.md).

## Install

| Language | Package | Install |
| - | - | - |
| TypeScript (Node.js ≥ 22.12) | `@grow-codes/graylog` | `npm install @grow-codes/graylog` |
| Rust (MSRV 1.88) | `grow-graylog` | `cargo add grow-graylog` |
| Go (1.26+) | `github.com/grow-codes-packages/graylog/go` | `go get github.com/grow-codes-packages/graylog/go` |
| Python (≥ 3.10) | `grow-graylog` | `pip install grow-graylog` |
| Java (17+) | `codes.grow.packages:graylog` | see below |

Maven:

```xml
<dependency>
  <groupId>codes.grow.packages</groupId>
  <artifactId>graylog</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle (Kotlin DSL):

```kotlin
implementation("codes.grow.packages:graylog:0.1.0")
```

## Quickstart

Every package reads its configuration from the environment or from an explicit config object
(see [Configuration](#configuration)). The examples check that Graylog is healthy, ship one record
through GELF TCP and read it back with a Lucene query.

```sh
export GROW_GRAYLOG_URL=http://127.0.0.1:9000
export GROW_GRAYLOG_API_TOKEN=...        # or GROW_GRAYLOG_USER + GROW_GRAYLOG_PASSWORD
export GROW_GRAYLOG_GELF_HOST=127.0.0.1  # a GELF TCP input on 12201 (ensureGelfInput creates one)
```

### TypeScript

```ts
import { GraylogClient } from "@grow-codes/graylog";

const client = GraylogClient.fromEnv();
try {
  const health = await client.health();
  console.log("healthy:", health.healthy, "version:", await client.serverVersion());

  // Ship logs through GELF (TCP by default): batched, redacted, never blocking the caller.
  const logs = client.logClient({ resource: { "service.name": "checkout" } });
  logs.logger("payments").error("payment failed", { order_id: "o-1", password: "never-sent" });
  await logs.flush();

  // Read it back (searchable about 1–2 s after ingest).
  const record = await client
    .logQueryClient()
    .waitForLog("order_id:o-1", { timeoutMs: 20_000 });
  console.log(record.severityText, record.body, record.resource["service.name"]);
} finally {
  await client.close();
}
```

### Rust

```rust
use std::time::Duration;
use grow_graylog::logging::{attrs, LogClient, LogQueryClient, WaitOptions};
use grow_graylog::{GraylogClient, LogOptions, LogQueryOptions};

#[tokio::main]
async fn main() -> grow_graylog::Result<()> {
    let client = GraylogClient::from_env()?;
    let health = client.health().await?;
    println!("healthy: {} version: {}", health.healthy, client.server_version().await?);

    let logs = client.new_log_client(
        LogOptions::default().resource_attribute("service.name", "checkout"),
    )?;
    logs.logger(Some("payments"), attrs! {})
        .error("payment failed", attrs! { "order_id" => "o-1", "password" => "never-sent" });
    logs.flush(None).await?;

    let record = client
        .log_query(LogQueryOptions::default())
        .wait_for_log("order_id:o-1", WaitOptions::default().timeout(Duration::from_secs(20)))
        .await?;
    println!("{} {}", record.severity, record.body);
    client.close().await;
    Ok(())
}
```

### Go

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	graylog "github.com/grow-codes-packages/graylog/go"
)

func main() {
	ctx := context.Background()
	client, err := graylog.NewClientFromEnv()
	if err != nil {
		log.Fatal(err) // CONFIG error naming the variable, never its value
	}
	defer client.Close()

	health, _ := client.Health(ctx)
	version, err := client.ServerVersion(ctx)
	fmt.Println("healthy:", health.Healthy, "version:", version, err)

	logs, err := client.NewLogClient(graylog.LogOptions{LogClientOptions: graylog.LogClientOptions{
		Resource: map[string]graylog.AttrValue{"service.name": "checkout"},
	}})
	if err != nil {
		log.Fatal(err)
	}
	logs.Logger("payments", nil).Error(ctx, "payment failed", "order_id", "o-1", "password", "never-sent")
	_ = logs.Flush(ctx)

	record, err := client.LogQuery(graylog.LogQueryOptions{}).
		WaitForLog(ctx, "order_id:o-1", graylog.WaitForLogOptions{Timeout: 20 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(record.SeverityText, record.Body)
}
```

### Python

```python
import grow_graylog as sdk

with sdk.GraylogClient.from_env() as client:
    health = client.health()
    print("healthy:", health.healthy, "version:", client.server_version())

    logs = client.log_client(resource={"service.name": "checkout"})
    logs.logger("payments").error("payment failed", {"order_id": "o-1", "password": "never-sent"})
    logs.flush()

    record = client.log_query_client().wait_for_log("order_id:o-1", timeout_s=20)
    print(record.severity, record.body, record.resource["service.name"])
```

### Java

```java
import codes.grow.packages.graylog.GraylogClient;
import codes.grow.packages.graylog.GraylogLogClientOptions;
import codes.grow.packages.graylog.logging.LogRecord;
import codes.grow.packages.graylog.logging.WaitForLogOptions;
import java.time.Duration;
import java.util.Map;

public final class Quickstart {
  public static void main(String[] args) {
    try (GraylogClient client = GraylogClient.fromEnv()) {
      var health = client.health();
      System.out.println("healthy: " + health.healthy() + " version: " + client.serverVersion());

      var logs =
          client.logClient(
              GraylogLogClientOptions.builder()
                  .resource(Map.of("service.name", "checkout"))
                  .build());
      logs.logger("payments")
          .error("payment failed", Map.of("order_id", "o-1", "password", "never-sent"));
      logs.flush();

      LogRecord record =
          client
              .logQueryClient()
              .waitForLog(
                  "order_id:o-1",
                  WaitForLogOptions.of(Duration.ofSeconds(20), Duration.ofSeconds(1)));
      System.out.println(record.severity() + " " + record.body());
    }
  }
}
```

More complete programs live in [examples/](examples/) — one folder per language.

## Configuration

All settings can be passed in code or through environment variables. Precedence: **explicit value >
`GROW_GRAYLOG_*` > vendor `GRAYLOG_*` > Grow stack aliases > default.** A present but invalid value
raises a `ConfigError` that names the variable (never its value).

| Setting | Environment variables | Default |
| - | - | - |
| `url` — REST base URL | `GROW_GRAYLOG_URL`, `GRAYLOG_URL` | `http://127.0.0.1:9000` |
| `apiToken` (secret; Basic `<token>:token`, wins over user/password) | `GROW_GRAYLOG_API_TOKEN`, `GRAYLOG_API_TOKEN` | none |
| `username` / `password` (secret) | `GROW_GRAYLOG_USER` / `GROW_GRAYLOG_PASSWORD`, `GRAYLOG_USER` / `GRAYLOG_PASSWORD` | none |
| `gelfHost` | `GROW_GRAYLOG_GELF_HOST`, `GRAYLOG_GELF_HOST`, stack alias `GRAYLOG_HOST` | host of `url` |
| `gelfPort` | `GROW_GRAYLOG_GELF_PORT`, `GRAYLOG_GELF_PORT`, stack alias `GRAYLOG_PORT` | 12201 (12202 for `http`) |
| `gelfProtocol` (`udp`, `tcp`, `http`) | `GROW_GRAYLOG_GELF_PROTOCOL`, `GRAYLOG_GELF_PROTOCOL`, stack alias `GRAYLOG_TRANSPORT` | `tcp` |
| `gelfHttpUrl` | `GROW_GRAYLOG_GELF_HTTP_URL`, `GRAYLOG_GELF_HTTP_URL` | `http(s)://<gelfHost>:<gelfPort>/gelf` |
| `gelfTls` (GELF TCP TLS, `https` GELF HTTP) | `GROW_GRAYLOG_GELF_TLS` | `false` |
| `otlpEndpoint` (OTLP/gRPC input) | `GROW_GRAYLOG_OTLP_ENDPOINT`, `GRAYLOG_OTLP_GRPC_ENDPOINT` | `http://<gelfHost>:4317` |
| `requestedBy` (`X-Requested-By` on non-GET requests) | — | `grow-codes-graylog` |
| `connectTimeout` | `GROW_GRAYLOG_CONNECT_TIMEOUT` | 10 s |
| `requestTimeout` (per attempt) | `GROW_GRAYLOG_REQUEST_TIMEOUT` | 30 s |
| `totalTimeout` (including retries) | `GROW_GRAYLOG_TOTAL_TIMEOUT` | 120 s |
| `retry.maxRetries` | `GROW_GRAYLOG_MAX_RETRIES` | 3 |
| `tls.caCertPath` | `GROW_GRAYLOG_CA_CERT` | system roots |
| `tls.clientCertPath` / `tls.clientKeyPath` | `GROW_GRAYLOG_CLIENT_CERT` / `GROW_GRAYLOG_CLIENT_KEY` | none |
| `tls.insecureSkipVerify` (tests only) | `GROW_GRAYLOG_INSECURE_SKIP_VERIFY` | `false` |
| `proxy` | `GROW_GRAYLOG_PROXY` | none (environment proxies are ignored) |
| `headers`, `userAgentSuffix`, `hooks`, `logger` | — | none |

Durations accept milliseconds (`1500`) or units (`500ms`, `10s`, `1m30s`); booleans accept
`true/false/1/0/yes/no/on/off`. Field names follow each language's convention (`api_token` in
Python and Rust, `APIToken` in Go). The full reference is in
[docs/configuration.md](docs/configuration.md).

## Function overview

<!-- service:function-overview — the service fills this section; keep the heading. -->

The same functions exist in every language, named per language convention (`listInputs` in
TypeScript and Java, `list_inputs` in Python and Rust, `ListInputs(ctx, …)` in Go). Every function
with a complete example per language: [docs/functions](https://grow-codes-packages.github.io/graylog/functions/).

### Client and status

| Function | Description |
| - | - |
| `fromEnv()` / constructor | immutable, validated config from code or `GROW_GRAYLOG_*` / `GRAYLOG_*` |
| `health()` | unauthenticated `lbstatus`: `ALIVE` → `ok`, `THROTTLED` → `degraded`, `DEAD` → `unhealthy`, network error → `unreachable`; never throws for an unhealthy server |
| `ping()` | authenticated round trip (`GET /api/system`), returns the latency |
| `serverVersion()` / `systemInfo()` | version (`7.0.16+58e0f6e`), node id, leader, lb status, timezone, … |
| `listFields()` | every indexed field name |
| `close()` | idempotent; flushes log clients, stops tails; later calls fail with `CANCELLED` |

<details><summary>TypeScript</summary>

```ts
const client = GraylogClient.fromEnv();
console.log((await client.health()).status, await client.serverVersion(), (await client.systemInfo()).nodeId);
await client.close();
```

</details>

<details><summary>Rust</summary>

```rust
let client = GraylogClient::from_env()?;
println!("{} {} {}", client.health().await?.status, client.server_version().await?, client.system_info().await?.node_id);
client.close().await;
```

</details>

<details><summary>Go</summary>

```go
client, err := graylog.NewClientFromEnv()
defer client.Close()
health, err := client.Health(ctx)
info, err := client.SystemInfo(ctx)
fmt.Println(health.Status, info.Version, info.NodeID)
```

</details>

<details><summary>Python</summary>

```python
with sdk.GraylogClient.from_env() as client:
    print(client.health().status, client.server_version(), client.system_info().node_id)
```

</details>

<details><summary>Java</summary>

```java
try (GraylogClient client = GraylogClient.fromEnv()) {
  System.out.println(client.health().status() + " " + client.serverVersion() + " " + client.systemInfo().nodeId());
}
```

</details>

### Admin: inputs, streams, index sets

| Function | Description |
| - | - |
| `listInputs()`, `getInput(id)`, `listInputTypes()`, `getInputState(id)` | read inputs and their runtime state |
| `createInput(type, config, {title, global, node})` | create any input; returns its id |
| `ensureGelfInput(protocol, port, opts)` | reuse a matching GELF input or create one, wait until `RUNNING`; a busy port → `CONFLICT` |
| `deleteInput(id)` | delete an input |
| `listStreams({page, perPage, query})`, `getStream(id)` | paginated streams |
| `createStream({title, rules, indexSetId, …})` | create a stream and resume it (Graylog creates streams paused) |
| `resumeStream(id)`, `deleteStream(id)` | start or delete a stream |
| `listIndexSets()` | index sets (the default one has `isDefault`) |

<details><summary>TypeScript</summary>

```ts
const input = await client.ensureGelfInput("tcp", 12201);
const streamId = await client.createStream({
  title: "checkout",
  rules: [{ field: "service_name", type: 1, value: "checkout", inverted: false, description: "" }],
});
console.log(input.created, (await client.listStreams()).total, (await client.listIndexSets()).length);
```

</details>

<details><summary>Rust</summary>

```rust
let input = client.ensure_gelf_input(GelfProtocol::Tcp, 12201, EnsureGelfInputOptions::default()).await?;
let stream_id = client
    .create_stream(CreateStreamOptions::new("checkout").rule(StreamRule::exact("service_name", "checkout")))
    .await?;
println!("{} {}", input.created, client.list_index_sets().await?.len());
```

</details>

<details><summary>Go</summary>

```go
input, err := client.EnsureGelfInput(ctx, graylog.GelfTCP, 12201, graylog.EnsureGelfInputOptions{})
streamID, err := client.CreateStream(ctx, graylog.CreateStreamOptions{Title: "checkout",
	Rules: []graylog.StreamRule{{Field: "service_name", Type: graylog.StreamRuleExact, Value: "checkout"}}})
sets, err := client.ListIndexSets(ctx)
```

</details>

<details><summary>Python</summary>

```python
inp = client.ensure_gelf_input("tcp", 12201)
stream_id = client.create_stream("checkout", rules=[sdk.StreamRule("service_name", 1, "checkout")])
print(inp.created, client.list_streams().total, len(client.list_index_sets()))
```

</details>

<details><summary>Java</summary>

```java
EnsuredInput input = client.ensureGelfInput(GelfProtocol.TCP, 12201, EnsureGelfInputOptions.defaults());
String streamId = client.createStream(CreateStreamOptions.builder("checkout")
    .rules(StreamRule.of("service_name", StreamRule.TYPE_EXACT, "checkout")).build());
System.out.println(input.created() + " " + client.listStreams().total());
```

</details>

### Search

| Function | Description |
| - | - |
| `search(query, {range \| from+to \| keyword, limit, offset, fields, sort, streams})` | Views search with a Lucene query; default last 300 s, 100 hits, newest first; `nextOffset` while more exist; query errors → `VALIDATION` |
| `searchRelative(query, seconds, opts)` | the same with a relative range |
| `getMessage(index, id)` | one stored message from a search hit |
| `logRecordFromMessage(fields)` | stored fields → normalized `LogRecord` (`service_name` → `service.name`, `source` → `host.name`, `level` → severity, `otel_*` fields) |

<details><summary>TypeScript</summary>

```ts
const page = await client.search("service_name:checkout AND level:<=3", { range: 600, limit: 20 });
const first = page.messages[0];
if (first) console.log((await client.getMessage(first.index, first.id)).fields.message);
```

</details>

<details><summary>Rust</summary>

```rust
let page = client.search_relative("service_name:checkout", Duration::from_secs(600), MessageSearchOptions::default()).await?;
if let Some(m) = page.messages.first() {
    println!("{:?}", client.get_message(&m.index, &m.id).await?.fields.get("message"));
}
```

</details>

<details><summary>Go</summary>

```go
res, err := client.Search(ctx, "service_name:checkout", graylog.MessageSearchOptions{Range: 10 * time.Minute, Limit: 20})
for _, r := range res.Records() {
	fmt.Println(r.SeverityText, r.Body)
}
```

</details>

<details><summary>Python</summary>

```python
page = client.search("service_name:checkout AND level:<=3", range_s=600, limit=20)
if page.messages:
    print(client.get_message(page.messages[0].index, page.messages[0].id).fields["message"])
```

</details>

<details><summary>Java</summary>

```java
MessageSearchResult page = client.searchRelative("service_name:checkout", Duration.ofMinutes(10));
page.records().forEach(r -> System.out.println(r.severity() + " " + r.body()));
```

</details>

### GELF messages and transports

| Function | Description |
| - | - |
| `GelfMessage` | GELF 1.1 builder: `host`, `shortMessage`, `fullMessage`, `timestamp`, `level` (syslog 0–7), validated `_additional` fields |
| `GelfUdpTransport` | one datagram per message, gzip/zlib/none, chunking up to 128 chunks; best-effort |
| `GelfTcpTransport` | NUL-framed JSON on one connection, TLS, reconnect with backoff |
| `GelfHttpTransport` | newline-delimited bulk `POST /gelf`, gzip |
| `gelfTransport(protocol)` | the transport for `udp`, `tcp` or `http` from the client configuration |
| `GelfLogExporter` | `LogExporter` over any GELF transport |

<details><summary>TypeScript</summary>

```ts
const tcp = client.gelfTransport("tcp");
await tcp.send([new GelfMessage({ host: "app-1", shortMessage: "hello", level: GelfLevel.Warning, fields: { k: "v" } })]);
await tcp.close();
```

</details>

<details><summary>Rust</summary>

```rust
let tcp = client.gelf_transport(Some(GelfProtocol::Tcp), GelfTransportOptions::default())?;
let msg = GelfMessage::new(GelfMessageOptions { host: "app-1".into(), short_message: "hello".into(), ..Default::default() })?;
tcp.send(&[msg], GelfSendOptions::default()).await?;
```

</details>

<details><summary>Go</summary>

```go
udp, err := client.GelfTransport(graylog.GelfUDP, graylog.GelfTransportOptions{})
msg, err := graylog.NewGelfMessage(graylog.GelfMessageOptions{Host: "app-1", ShortMessage: "hello"})
res, err := udp.Send(ctx, []*graylog.GelfMessage{msg}, graylog.GelfSendOptions{})
```

</details>

<details><summary>Python</summary>

```python
http = client.gelf_transport("http")
http.send([sdk.GelfMessage("app-1", "hello", level=sdk.GelfLevel.WARNING, fields={"k": "v"})])
http.close()
```

</details>

<details><summary>Java</summary>

```java
GelfTransport tcp = client.gelfTransport(GelfProtocol.TCP);
tcp.send(List.of(GelfMessage.builder("app-1", "hello").level(4).field("k", "v").build()));
tcp.close();
```

</details>

### Logging: log client, OTLP and log query

| Function | Description |
| - | - |
| `logClient({protocol: tcp \| udp \| http \| otlp, resource, …})` | batching `LogClient` (queue limits, drop policy, redaction, `stats()`), logger facade with trace correlation, framework adapters |
| `OtlpGrpcLogExporter` | OTLP/gRPC logs to Graylog's OpenTelemetry input (gzip, partial success, gRPC status mapping) |
| `logQueryClient({streams, defaultWindow})` | `search(query, {start, end, limit, order, cursor})`, `tail(query, onRecord)` (polls every 2 s), `listStreams()`, `listLabels()`, `waitForLog(query, {timeout})` |
| adapters | TypeScript pino/winston, Rust `tracing` layer + `log`, Go `slog.Handler` + zap core, Python `logging.Handler` + structlog, Java Logback/Log4j2/JUL |

<details><summary>TypeScript</summary>

```ts
const logs = client.logClient({ protocol: "otlp", resource: { "service.name": "checkout" } });
logs.logger("api").warn("slow request", { ms: 1800 });
await logs.flush();
const handle = client.logQueryClient().tail("service_name:checkout", (r) => console.log(r.body));
handle.stop();
```

</details>

<details><summary>Rust</summary>

```rust
let logs = client.new_log_client(LogOptions::default().protocol(GelfProtocol::Udp).resource_attribute("service.name", "checkout"))?;
logs.logger(Some("api"), attrs! {}).warn("slow request", attrs! { "ms" => 1800 });
logs.flush(None).await?;
let records = client.log_query(LogQueryOptions::default()).search("service_name:checkout", SearchOptions::default()).await?;
```

</details>

<details><summary>Go</summary>

```go
logs, err := client.NewLogClient(graylog.LogOptions{Protocol: graylog.GelfHTTP})
logs.Logger("api", nil).Warn(ctx, "slow request", "ms", 1800)
_ = logs.Flush(ctx)
handle, err := client.LogQuery(graylog.LogQueryOptions{}).Tail(ctx, "service_name:checkout",
	func(r graylog.LogRecord) { fmt.Println(r.Body) }, graylog.TailOptions{})
defer handle.Stop()
```

</details>

<details><summary>Python</summary>

```python
logs = client.log_client("udp", resource={"service.name": "checkout"})
logs.logger("api").warn("slow request", {"ms": 1800})
logs.flush()
record = client.log_query_client().wait_for_log("service_name:checkout", timeout_s=20)
```

</details>

<details><summary>Java</summary>

```java
BatchingLogClient logs = client.logClient(GraylogLogClientOptions.builder().protocol(GelfProtocol.HTTP).build());
logs.logger("api").warn("slow request", Map.of("ms", 1800));
logs.flush();
TailHandle handle = client.logQueryClient().tail("service_name:checkout", r -> System.out.println(r.body()));
handle.stop();
```

</details>

<!-- /service:function-overview -->

## Testing with Docker

The integration suite runs every public function against a real Graylog Open
(`graylog/graylog:7.0` + OpenSearch + MongoDB) in Docker. A bootstrap container creates GELF UDP,
TCP and HTTP inputs, an OpenTelemetry gRPC input and an API token. Each language package is packed
and installed into a separate consumer project first, so the tests use the package exactly as you
would; the shared conformance scenarios run too.

```sh
make test-docker                     # all five languages
make test-docker LANGS="go python"   # a subset
GRAYLOG_SDK_MONGO_IMAGE=mongo:7.0.48-jammy make test-docker   # choose the MongoDB image yourself
```

No host ports are published and every run uses its own Compose project, so runs never collide; the
stack is always removed afterwards (`docker compose down -v`). OpenSearch needs
`vm.max_map_count >= 262144` on the host. On Linux kernels 6.19–7.0.13 MongoDB 8 crashes, so the
Makefile switches the fixture to MongoDB 7 there. Unit tests need no Docker: `make test` or
`make coverage`.

## Compatibility

| | TypeScript | Rust | Go | Python | Java |
| - | - | - | - | - | - |
| Runtime | Node.js ≥ 22.12, ESM + CJS | stable, MSRV 1.88 | 1.26, 1.27 | 3.10 – 3.14 | 17, 21, 25 |
| Async | `Promise` + `AbortSignal` | `async` (tokio), `blocking` feature | `context.Context` | sync + `asyncio` | sync + `CompletableFuture` |
| GELF UDP / TCP / HTTP | yes | yes | yes | yes | yes |
| OTLP/gRPC | built in (`node:http2`) | built in (HTTP/2) | built in (grpc-go) | extra `grow-graylog[otlp]` | built in (OkHttp) |
| Graylog Open | 7.0 | 7.0 | 7.0 | 7.0 | 7.0 |

Cases the container cannot produce (throttled/dead nodes, 403, TLS inputs, UDP guarantees, the
128-chunk ceiling) are unit-tested and listed with the language differences in
[docs/compatibility.md](docs/compatibility.md).

## Contributing

Contributions are welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) and
[AGENTS.md](AGENTS.md) first. All five languages keep the same API; a change lands in all of them
together. Parts of this repository are generated by
[sdk-kit](https://github.com/grow-codes-packages/sdk-kit) and changed there.

## Security

Please report vulnerabilities privately to [opensource@grow.codes](mailto:opensource@grow.codes).
See [SECURITY.md](SECURITY.md).

## Licence

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for attributions.

## Trademarks and disclaimer

This is an independent, community-maintained project. It is **not affiliated with, endorsed or
sponsored by Graylog, Inc.** Graylog and Graylog Open are trademarks of Graylog, Inc.; they are used
here only to name the service this SDK connects to. MongoDB and OpenSearch appear only in the
Docker test fixture. The Graylog Open server is licensed separately by its owner
(SSPL-1.0 (source-available)).

The software is provided "AS IS", without warranties or conditions of any kind. Grow Codes is not
responsible for any damage, data loss, security incident, outage or cost that results from using it.
See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## About Grow Codes

This SDK is built and maintained by [Grow Codes](https://grow.codes). Grow Codes publishes the
client libraries it builds as open source in the
[grow-codes-packages](https://github.com/grow-codes-packages) organisation, generated from one
shared kit so that every service and every language behaves the same way. Learn more at
[grow.codes](https://grow.codes).
