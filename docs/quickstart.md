# Quickstart

Connect to Graylog Open, check that it is healthy, ship a log record through GELF and read it back
with a Lucene query. The client reads `GROW_GRAYLOG_*` (or the vendor `GRAYLOG_*`) variables listed
in [Configuration](configuration.md#graylog-settings), or takes the values in code.

```sh
export GROW_GRAYLOG_URL=http://127.0.0.1:9000
export GROW_GRAYLOG_API_TOKEN=...        # or GROW_GRAYLOG_USER + GROW_GRAYLOG_PASSWORD; never commit real tokens
export GROW_GRAYLOG_GELF_HOST=127.0.0.1  # GELF TCP input on 12201 (default protocol tcp)
```

The Graylog server needs a GELF input on that port; `ensureGelfInput("tcp", 12201)` creates one
when it is missing ([Admin](functions/admin.md)).

=== "TypeScript"

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

=== "Rust"

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

=== "Go"

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

=== "Python"

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

=== "Java"

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

Next: every function with examples on the [Functions](functions.md) pages, error handling in
[Error handling](errors.md) and the Docker fixture in [Docker testing](docker-testing.md).
