# Client and status

Create one client per process, reuse it everywhere and close it on shutdown. `close()` is
idempotent: it flushes and closes every log client created from this client, stops open tails and
releases connections. **Every call on a closed client fails with `CANCELLED`** ("client is
closed"), in all five languages; creating a log client or a tail on a closed client fails the same
way.

| Function | Graylog API | Result |
| - | - | - |
| `fromEnv()` | — | client configured from `GROW_GRAYLOG_*` / `GRAYLOG_*` ([Configuration](../configuration.md#graylog-settings)) |
| `health()` | `GET /api/system/lbstatus` with `Accept: text/plain`, no credentials | `ALIVE` → healthy `ok`; 429 `THROTTLED` → `degraded`; 503 `DEAD` → `unhealthy`; network error → `unreachable`. Never throws for an unhealthy or unreachable server (only `CANCELLED` and `CONFIG`). `details.lb_status` holds Graylog's word. |
| `ping()` | `GET /api/system` with credentials | latency of an authenticated call; `AUTHENTICATION` for a wrong token or password |
| `serverVersion()` | `GET /api/system` | Graylog's version string as reported, e.g. `7.0.16+58e0f6e` (the build suffix is kept) |
| `systemInfo()` | `GET /api/system` | `facility`, `codename`, `nodeId`, `clusterId`, `version`, `startedAt`, `hostname`, `lifecycle`, `lbStatus`, `timezone`, `operatingSystem`, `isLeader`, `isProcessing` |
| `listFields()` | `GET /api/system/fields` | every indexed field name (also `logQueryClient().listLabels()`) |
| `close()` | — | flush log clients, stop tails, release connections |

Every non-GET request carries `X-Requested-By` (Graylog's CSRF guard answers 400 without it); the
value is `grow-codes-graylog` unless `requestedBy` is set. REST authentication is HTTP Basic: an
API token is sent as `<token>:token`, otherwise `username:password`; the token wins when both are
set.

=== "TypeScript"

    ```ts
    import { GraylogClient } from "@grow-codes/graylog";

    const client = GraylogClient.fromEnv();
    try {
      const health = await client.health(); // { healthy, status, details: { lb_status } }
      if (!health.healthy) console.warn("Graylog is not ready:", health.status);
      console.log(await client.ping({ signal: AbortSignal.timeout(5_000) }), "ms");
      console.log(await client.serverVersion()); // "7.0.16+58e0f6e"
      const info = await client.systemInfo();
      console.log(info.nodeId, info.isLeader, info.lbStatus);
      console.log((await client.listFields()).length, "indexed fields");
    } finally {
      await client.close();
    }
    ```

=== "Rust"

    ```rust
    use grow_graylog::GraylogClient;

    let client = GraylogClient::from_env()?;
    let health = client.health().await?;
    if !health.healthy {
        eprintln!("Graylog is not ready: {}", health.status);
    }
    println!("{:?}", client.ping().await?);
    println!("{}", client.server_version().await?);
    let info = client.system_info().await?;
    println!("{} {}", info.node_id, info.lb_status);
    println!("{} indexed fields", client.list_fields().await?.len());
    client.close().await;
    ```

=== "Go"

    ```go
    client, err := graylog.NewClientFromEnv()
    if err != nil {
    	return err
    }
    defer client.Close()

    health, err := client.Health(ctx)
    if err != nil {
    	return err
    }
    fmt.Println(health.Healthy, health.Status)
    latency, err := client.Ping(ctx) // time.Duration
    version, err := client.ServerVersion(ctx)
    info, err := client.SystemInfo(ctx)
    fmt.Println(latency, version, info.NodeID, info.IsLeader)
    fields, err := client.ListFields(ctx)
    ```

=== "Python"

    ```python
    import grow_graylog as sdk

    with sdk.GraylogClient.from_env() as client:
        health = client.health()
        if not health.healthy:
            print("Graylog is not ready:", health.status)
        print(f"{client.ping():.1f} ms", client.server_version())
        info = client.system_info()
        print(info.node_id, info.is_leader, info.lb_status)
        print(len(client.list_fields()), "indexed fields")

    # async: the same methods on AsyncGraylogClient
    async with sdk.AsyncGraylogClient.from_env() as aclient:
        print(await aclient.server_version())
    ```

=== "Java"

    ```java
    import codes.grow.packages.graylog.GraylogClient;

    try (GraylogClient client = GraylogClient.fromEnv()) {
      var health = client.health();
      if (!health.healthy()) System.err.println("Graylog is not ready: " + health.status());
      System.out.println(client.ping()); // Duration
      System.out.println(client.serverVersion());
      var info = client.systemInfo();
      System.out.println(info.nodeId() + " " + info.isLeader());
      System.out.println(client.listFields().size() + " indexed fields");
      client.serverVersionAsync().thenAccept(System.out::println).join();
    }
    ```
