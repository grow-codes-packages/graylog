# Log client, OTLP and log query

The [logging category](../logging.md) interface (`LogClient`, `Logger`, `BatchProcessor`,
`RedactionProcessor`, framework adapters, `LogQueryClient`) is the same in every Grow Codes SDK.
This page shows the Graylog-specific parts.

## `logClient` — send logs

`logClient({protocol, …})` returns a batching `LogClient` that sends through:

| `protocol` | Exporter | Default endpoint |
| - | - | - |
| `tcp` (default, `gelfProtocol`) | `GelfLogExporter` over `GelfTcpTransport` | `gelfHost:gelfPort` (12201) |
| `udp` | `GelfLogExporter` over `GelfUdpTransport` (gzip, chunked) | `gelfHost:gelfPort` (12201) |
| `http` | `GelfLogExporter` over `GelfHttpTransport` (bulk, gzip) | `gelfHttpUrl` or `http://gelfHost:12202/gelf` |
| `otlp` | `OtlpGrpcLogExporter` (OTLP/gRPC `LogsService/Export`, gzip, partial success) | `otlpEndpoint` or `http://gelfHost:4317` |

Further options: `host` (GELF `host`, default the machine name), `resource` (`service.name`, …),
batching (`maxQueueSize`, `maxBatchSize`, `flushInterval`, drop policy, …), `redaction`, and the
transport options `compression`/`chunkSize` (UDP), `bulk`/`headers` (HTTP), `bearerToken`/`headers`
(OTLP), or an explicit `transport`. `close()` of the Graylog client flushes and closes every log
client it created.

**OTLP/gRPC** goes to Graylog's *OpenTelemetry (gRPC)* input (Graylog Open 7.0 has no OTLP/HTTP
input). Graylog stores OTLP records as `otel_*` fields (`otel_trace_id`, `otel_severity_text`,
`otel_resource_attributes_service_name`, `otel_attributes_<key>`, …); search maps them back.
gRPC statuses map to SDK errors (`UNAVAILABLE`/`RESOURCE_EXHAUSTED` retryable,
`UNAUTHENTICATED` → `AUTHENTICATION`, `PERMISSION_DENIED`, `INVALID_ARGUMENT` → `VALIDATION`,
`DEADLINE_EXCEEDED` → `TIMEOUT`). Python needs the optional extra `pip install
"grow-graylog[otlp]"` (grpcio); Java uses OkHttp (HTTP/2); TypeScript, Rust and Go need nothing
extra.

=== "TypeScript"

    ```ts
    const logs = client.logClient({
      protocol: "http",
      resource: { "service.name": "checkout", "deployment.environment": "prod" },
    });
    const log = logs.logger("payments", { region: "eu" });
    log.info("order placed", { order_id: "o-1", amount: 42.5 });
    log.error("payment failed", { password: "never-sent" }); // redacted before it leaves
    await logs.flush();

    const otlp = client.logClient({ protocol: "otlp" }); // endpoint from otlpEndpoint
    otlp.send({ message: "via OTLP", attributes: { k: "v" } });
    await client.close(); // flushes both
    ```

=== "Rust"

    ```rust
    use grow_graylog::logging::{attrs, LogClient};
    use grow_graylog::{GelfProtocol, LogOptions};

    let logs = client.new_log_client(
        LogOptions::default()
            .protocol(GelfProtocol::Http)
            .resource_attribute("service.name", "checkout"),
    )?;
    let log = logs.logger(Some("payments"), attrs! { "region" => "eu" });
    log.info("order placed", attrs! { "order_id" => "o-1", "amount" => 42.5 });
    logs.flush(None).await?;

    let otlp = client.new_log_client(LogOptions::default().protocol(GelfProtocol::Otlp))?;
    otlp.send("via OTLP".into());
    client.close().await; // flushes both
    ```

=== "Go"

    ```go
    logs, err := client.NewLogClient(graylog.LogOptions{
    	Protocol: graylog.GelfHTTP,
    	LogClientOptions: graylog.LogClientOptions{
    		Resource: map[string]graylog.AttrValue{"service.name": "checkout"},
    	},
    })
    if err != nil {
    	return err
    }
    log := logs.Logger("payments", map[string]graylog.AttrValue{"region": "eu"})
    log.Info(ctx, "order placed", "order_id", "o-1", "amount", 42.5)
    if err := logs.Flush(ctx); err != nil {
    	return err
    }

    otlp, err := client.NewLogClient(graylog.LogOptions{Protocol: graylog.ProtocolOTLP})
    otlp.Send(ctx, graylog.LogInput{Message: "via OTLP"})
    ```

=== "Python"

    ```python
    logs = client.log_client(
        "http",
        resource={"service.name": "checkout", "deployment.environment": "prod"},
    )
    log = logs.logger("payments", {"region": "eu"})
    log.info("order placed", {"order_id": "o-1", "amount": 42.5})
    logs.flush()

    otlp = client.log_client("otlp")  # needs grow-graylog[otlp]
    otlp.logger().warn("via OTLP", {"k": "v"})
    client.close()  # flushes both
    ```

=== "Java"

    ```java
    import codes.grow.packages.graylog.logging.BatchingLogClient;
    import java.util.Map;

    BatchingLogClient logs =
        client.logClient(
            GraylogLogClientOptions.builder()
                .protocol(GelfProtocol.HTTP)
                .resource(Map.of("service.name", "checkout"))
                .build());
    var log = logs.logger("payments", Map.of("region", "eu"));
    log.info("order placed", Map.of("order_id", "o-1", "amount", 42.5));
    logs.flush();

    BatchingLogClient otlp =
        client.logClient(GraylogLogClientOptions.builder().protocol(GelfProtocol.OTLP).build());
    otlp.logger().warn("via OTLP");
    client.close(); // flushes both
    ```

## `logQueryClient` — read logs back

`logQueryClient({streams, defaultWindow = 1 h})` returns the category `LogQueryClient` on top of
[`search`](search.md):

| Function | Behaviour |
| - | - |
| `search(query, {start, end, limit = 100, order = "desc", cursor})` | normalized `LogRecord`s; `start` defaults to `end` − 1 h, `end` to now; ties broken by `gl2_message_id`; the cursor is the offset of the next page |
| `tail(query, onRecord, {start, interval})` | **polls** search (Graylog has no streaming API) every **2 s** and calls `onRecord` once per new record, oldest first. It delivers only records at or after its start (default: now). Each poll looks back 10 s before the newest record seen and drops duplicates by message id, so records that become searchable late are still delivered. Search errors go to `onError` (TypeScript, Python, Java) or the SDK logger (Rust, Go) and polling continues. Stops with the handle or `close()` of the client; on a closed client it fails with `CANCELLED`. |
| `listStreams()` | stream titles (all pages) |
| `listLabels()` | indexed field names (`listFields()`) |
| `waitForLog(query, {timeout = 30 s, interval = 1 s, predicate})` | polls `search` until a record matches; `TIMEOUT` otherwise (test helper) |

**Tail interval.** An explicit interval is honoured as given; zero or a negative value means the
2 s default. Two languages inherit a 1 s default from the shared `TailOptions` type: in **Rust**
an interval equal to that template default (1 s) is treated as unset and becomes 2 s (pass e.g.
`Duration::from_millis(1001)` for about one second); in **Java** `tail(query, onRecord)` uses 2 s,
while `tail(query, onRecord, TailOptions.defaults())` polls every 1 s like any explicit interval.

=== "TypeScript"

    ```ts
    const query = client.logQueryClient({ streams: [streamId] });
    const page = await query.search("service_name:checkout AND level:<=3", { limit: 20 });
    for (const r of page.records) console.log(r.timestamp, r.severityText, r.body);
    if (page.nextCursor) await query.search("service_name:checkout", { cursor: page.nextCursor });

    const handle = query.tail("service_name:checkout", (r) => console.log("live:", r.body), {
      onError: (e) => console.warn(e),
    });
    // … later
    handle.stop();

    const record = await query.waitForLog(`order_id:o-1`, { timeoutMs: 20_000 });
    console.log(await query.listStreams(), (await query.listLabels()).length);
    ```

=== "Rust"

    ```rust
    use std::sync::Arc;
    use std::time::Duration;
    use grow_graylog::logging::{LogQueryClient, SearchOptions, TailOptions, WaitOptions};
    use grow_graylog::LogQueryOptions;

    let query = client.log_query(LogQueryOptions::default());
    let page = query.search("service_name:checkout", SearchOptions::default()).await?;
    for r in &page.records {
        println!("{} {}", r.severity, r.body);
    }
    let handle = query
        .tail(
            "service_name:checkout",
            Arc::new(|r| println!("live: {}", r.body)),
            TailOptions::default(), // 2 s
        )
        .await?;
    handle.stop();
    let record = query
        .wait_for_log("order_id:o-1", WaitOptions::default().timeout(Duration::from_secs(20)))
        .await?;
    println!("{:?}", query.list_streams().await?);
    ```

=== "Go"

    ```go
    query := client.LogQuery(graylog.LogQueryOptions{Streams: []string{streamID}})
    page, err := query.Search(ctx, "service_name:checkout", graylog.SearchOptions{Limit: 20})
    for _, r := range page.Records {
    	fmt.Println(r.Timestamp, r.SeverityText, r.Body)
    }
    handle, err := query.Tail(ctx, "service_name:checkout", func(r graylog.LogRecord) {
    	fmt.Println("live:", r.Body)
    }, graylog.TailOptions{}) // 2 s
    defer handle.Stop()
    record, err := query.WaitForLog(ctx, "order_id:o-1", graylog.WaitForLogOptions{Timeout: 20 * time.Second})
    streams, err := query.ListStreams(ctx)
    labels, err := query.ListLabels(ctx)
    ```

=== "Python"

    ```python
    query = client.log_query_client(streams=[stream_id])
    page = query.search("service_name:checkout AND level:<=3", limit=20)
    for r in page.records:
        print(r.timestamp, r.severity, r.body)

    handle = query.tail("service_name:checkout", lambda r: print("live:", r.body))
    ...
    handle.stop()

    record = query.wait_for_log("order_id:o-1", timeout_s=20)
    print(query.list_streams(), len(query.list_labels()))

    # async: AsyncGraylogClient.log_query_client() has the same methods (await tail/stop)
    ```

=== "Java"

    ```java
    import codes.grow.packages.graylog.logging.*;
    import java.time.Duration;

    GraylogLogQueryClient query = client.logQueryClient();
    LogSearchResult page = query.search("service_name:checkout");
    page.records().forEach(r -> System.out.println(r.severity() + " " + r.body()));

    TailHandle handle =
        query.tail("service_name:checkout", r -> System.out.println("live: " + r.body())); // 2 s
    handle.stop();

    LogRecord record =
        query.waitForLog("order_id:o-1", WaitForLogOptions.of(Duration.ofSeconds(20), Duration.ofSeconds(1)));
    System.out.println(query.listStreams() + " " + query.listLabels().size());
    ```
