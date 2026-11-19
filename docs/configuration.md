# Configuration

`GraylogConfig` holds every setting of a client. It is **immutable** after construction,
validated when it is built (invalid values raise a `CONFIG` error) and its string/debug form
**redacts every credential**. The Graylog fields (credentials, GELF and OTLP endpoints) are listed
under [Graylog settings](#graylog-settings).

## Common settings

| Setting | Default | Environment variable |
| - | - | - |
| `url` — endpoint base URL | `http://127.0.0.1:9000` | `GROW_GRAYLOG_URL` |
| `connectTimeout` — connection setup | 10 s | `GROW_GRAYLOG_CONNECT_TIMEOUT` |
| `requestTimeout` — per attempt (headers + body) | 30 s | `GROW_GRAYLOG_REQUEST_TIMEOUT` |
| `totalTimeout` — whole call incl. retries and backoff | 120 s | `GROW_GRAYLOG_TOTAL_TIMEOUT` |
| `retry` — retry policy (below) | 3 retries | `GROW_GRAYLOG_MAX_RETRIES` |
| `tls.caCertPath` / `tls.caCertPem` — extra CA | none | `GROW_GRAYLOG_CA_CERT` (path) |
| `tls.clientCertPath` + `tls.clientKeyPath` — mutual TLS | none | `GROW_GRAYLOG_CLIENT_CERT`, `GROW_GRAYLOG_CLIENT_KEY` |
| `tls.insecureSkipVerify` — tests only, logs a warning once | `false` | `GROW_GRAYLOG_INSECURE_SKIP_VERIFY` |
| `proxy` — proxy URL | none (environment proxies are **ignored**) | `GROW_GRAYLOG_PROXY` |
| `headers` — extra request headers | `{}` | — |
| `userAgentSuffix` — appended to the User-Agent | none | — |
| `hooks` — request/response callbacks ([Hooks](hooks.md)) | none | — |
| `logger` — diagnostic logger ([Hooks](hooks.md)) | silent | — |

Every request sends `User-Agent: grow-codes-graylog/<version> (<language>)`.

## From the environment

`fromEnv` resolves each setting with this precedence:

1. the value passed in code (overrides),
2. `GROW_GRAYLOG_<NAME>`,
3. the vendor variables `GRAYLOG_*` ([Graylog settings](#graylog-settings)),
4. the platform stack aliases `GRAYLOG_HOST`, `GRAYLOG_PORT`, `GRAYLOG_TRANSPORT`,
5. the default.

Parsing rules:

- **Durations** accept integer milliseconds (`1500`) or Go-style units: `500ms`, `10s`, `2m`, `1h`,
  combinations such as `1m30s`.
- **Booleans** accept `true/false`, `1/0`, `yes/no`, `on/off` (any case).
- An **empty** variable counts as unset.
- A present but **invalid** value raises a `CONFIG` error that names the variable, never its value.

=== "TypeScript"

    ```ts
    import { GraylogClient, GraylogConfig } from "@grow-codes/graylog";

    // Environment only
    const client = GraylogClient.fromEnv();

    // Environment with explicit overrides (explicit values win)
    const config = GraylogConfig.fromEnv({ requestTimeoutMs: 5_000 });

    // Everything in code
    const explicit = new GraylogConfig({
      url: "https://graylog.example.com",
      apiToken: process.env.MY_GRAYLOG_TOKEN,
      gelfHost: "graylog.example.com",
      gelfProtocol: "http",
      connectTimeoutMs: 5_000,
      requestTimeoutMs: 15_000,
      totalTimeoutMs: 60_000,
      retry: { maxRetries: 5, initialBackoffMs: 200 },
      tls: { caCertPath: "/etc/ssl/internal-ca.pem" },
      proxy: "http://proxy.internal:3128",
      headers: { "x-team": "payments" },
      userAgentSuffix: "my-app/1.4",
    });
    const custom = new GraylogClient(explicit);
    console.log(String(explicit)); // apiToken shown as [REDACTED]
    ```

=== "Rust"

    ```rust
    use std::time::Duration;
    use grow_graylog::{GelfProtocol, GraylogClient, GraylogConfig, RetryPolicy};

    // Environment only
    let client = GraylogClient::from_env()?;

    // Environment with explicit overrides (explicit values win)
    let config = GraylogConfig::builder()
        .request_timeout(Duration::from_secs(5))
        .build_from_env()?;

    // Everything in code
    let explicit = GraylogConfig::builder()
        .url("https://graylog.example.com")
        .api_token(std::env::var("MY_GRAYLOG_TOKEN").unwrap_or_default())
        .gelf_host("graylog.example.com")
        .gelf_protocol(GelfProtocol::Http)
        .connect_timeout(Duration::from_secs(5))
        .request_timeout(Duration::from_secs(15))
        .total_timeout(Duration::from_secs(60))
        .retry(RetryPolicy::default().with_max_retries(5))
        .ca_cert_path("/etc/ssl/internal-ca.pem")
        .proxy("http://proxy.internal:3128")
        .header("x-team", "payments")
        .user_agent_suffix("my-app/1.4")
        .build()?;
    let custom = GraylogClient::new(explicit)?;
    println!("{:?}", custom.config()); // api_token shown as [REDACTED]
    ```

=== "Go"

    ```go
    // Environment only
    client, err := graylog.NewClientFromEnv()

    // Everything in code: zero values mean "use the default"
    cfg := graylog.Config{
        CommonConfig: graylog.CommonConfig{
            URL:             "https://graylog.example.com",
            ConnectTimeout:  5 * time.Second,
            RequestTimeout:  15 * time.Second,
            TotalTimeout:    time.Minute,
            Retry:           &graylog.RetryPolicy{MaxRetries: 5, InitialBackoff: 200 * time.Millisecond},
            TLS:             graylog.TLSConfig{CACertPath: "/etc/ssl/internal-ca.pem"},
            Proxy:           "http://proxy.internal:3128",
            Headers:         map[string]string{"x-team": "payments"},
            UserAgentSuffix: "my-app/1.4",
        },
        APIToken:     graylog.NewSecret(os.Getenv("MY_GRAYLOG_TOKEN")),
        GelfHost:     "graylog.example.com",
        GelfProtocol: graylog.GelfHTTP,
    }
    if err := cfg.Validate(); err != nil {
        log.Fatal(err) // errors.Is(err, graylog.ErrConfig)
    }
    custom, err := graylog.NewClient(cfg)

    // Environment with explicit overrides (explicit values win; nil env = process environment)
    merged, err := graylog.ConfigFromEnvWith(graylog.Config{
        CommonConfig: graylog.CommonConfig{RequestTimeout: 5 * time.Second},
    }, nil)
    fmt.Println(merged) // APIToken shown as [REDACTED]
    ```

=== "Python"

    ```python
    import os
    from grow_graylog import RetryPolicy, TlsConfig, GraylogClient, GraylogConfig

    # Environment only
    client = GraylogClient.from_env()

    # Environment with explicit overrides (explicit values win)
    config = GraylogConfig.from_env(request_timeout=5.0)

    # Everything in code: durations are float seconds (datetime.timedelta also works)
    explicit = GraylogConfig(
        url="https://graylog.example.com",
        api_token=os.environ.get("MY_GRAYLOG_TOKEN"),
        gelf_host="graylog.example.com",
        gelf_protocol="http",
        connect_timeout=5.0,
        request_timeout=15.0,
        total_timeout=60.0,
        retry=RetryPolicy(max_retries=5, initial_backoff=0.2),
        tls=TlsConfig(ca_cert_path="/etc/ssl/internal-ca.pem"),
        proxy="http://proxy.internal:3128",
        headers={"x-team": "payments"},
        user_agent_suffix="my-app/1.4",
    )
    custom = GraylogClient(explicit)
    print(repr(explicit))  # api_token shown as [REDACTED]
    ```

=== "Java"

    ```java
    import java.time.Duration;
    import codes.grow.packages.graylog.GelfProtocol;
    import codes.grow.packages.graylog.GraylogClient;
    import codes.grow.packages.graylog.GraylogConfig;
    import codes.grow.packages.graylog.core.RetryPolicy;

    // Environment only
    GraylogClient client = GraylogClient.fromEnv();

    // Everything in code
    GraylogConfig config = GraylogConfig.builder()
        .url("https://graylog.example.com")
        .apiToken(System.getenv("MY_GRAYLOG_TOKEN"))
        .gelfHost("graylog.example.com")
        .gelfProtocol(GelfProtocol.HTTP)
        .connectTimeout(Duration.ofSeconds(5))
        .requestTimeout(Duration.ofSeconds(15))
        .totalTimeout(Duration.ofMinutes(1))
        .retry(RetryPolicy.builder().maxRetries(5).initialBackoff(Duration.ofMillis(200)).build())
        .proxy("http://proxy.internal:3128")
        .header("x-team", "payments")
        .userAgentSuffix("my-app/1.4")
        .build();
    GraylogClient custom = GraylogClient.create(config);
    System.out.println(config); // apiToken shown as [REDACTED]
    ```

## Graylog settings

| Setting | Default | Environment variables (precedence order) |
| - | - | - |
| `apiToken` (secret) — REST API token, sent as HTTP Basic `<token>:token`; wins over user/password | none | `GROW_GRAYLOG_API_TOKEN`, `GRAYLOG_API_TOKEN` |
| `username` + `password` (secret) — REST HTTP Basic credentials | none | `GROW_GRAYLOG_USER` / `GROW_GRAYLOG_PASSWORD`, `GRAYLOG_USER` / `GRAYLOG_PASSWORD` |
| `url` — REST base URL (paths start with `/api`) | `http://127.0.0.1:9000` | `GROW_GRAYLOG_URL`, `GRAYLOG_URL` |
| `gelfHost` — GELF host | host of `url` | `GROW_GRAYLOG_GELF_HOST`, `GRAYLOG_GELF_HOST`, platform `GRAYLOG_HOST` |
| `gelfPort` — GELF port | 12202 for `http`, 12201 otherwise | `GROW_GRAYLOG_GELF_PORT`, `GRAYLOG_GELF_PORT`, platform `GRAYLOG_PORT` |
| `gelfProtocol` — default GELF transport `udp`, `tcp` or `http` | `tcp` | `GROW_GRAYLOG_GELF_PROTOCOL`, `GRAYLOG_GELF_PROTOCOL`, platform `GRAYLOG_TRANSPORT` |
| `gelfHttpUrl` — full GELF HTTP endpoint | `http(s)://<gelfHost>:<gelfPort>/gelf` | `GROW_GRAYLOG_GELF_HTTP_URL`, `GRAYLOG_GELF_HTTP_URL` |
| `gelfTls` — TLS for GELF TCP (and `https` for the default GELF HTTP URL), with the `tls` settings | `false` | `GROW_GRAYLOG_GELF_TLS` |
| `otlpEndpoint` — OTLP/gRPC endpoint of a Graylog *OpenTelemetry (gRPC)* input | `http://<gelfHost>:4317` | `GROW_GRAYLOG_OTLP_ENDPOINT`, `GRAYLOG_OTLP_GRPC_ENDPOINT` |
| `requestedBy` — `X-Requested-By` header on non-GET requests (Graylog's CSRF guard) | `grow-codes-graylog` | — |

Names per language: TypeScript `apiToken`, `gelfHttpUrl`; Rust `api_token`, `gelf_http_url`; Go
`APIToken`, `GelfHTTPURL`, `GelfTLS`, `OTLPEndpoint`; Python `api_token`, `gelf_http_url`; Java
`apiToken(…)`, `basicAuth(user, password)`, `gelfHttpUrl(…)`.

The platform aliases `GRAYLOG_HOST`, `GRAYLOG_PORT` and `GRAYLOG_TRANSPORT` are the variables that
Grow Codes stacks set for their Graylog service (TCP and UDP on 12201); they have the lowest
priority. `validate()` raises `CONFIG` for an invalid URL, a blank API token, a username without a password
(or the reverse), a port outside 1–65535, an unknown GELF protocol (`otlp` is a log client
protocol, not a `gelfProtocol`), a non-HTTP(S) `gelfHttpUrl`/`otlpEndpoint` or a blank
`requestedBy`.

## Retry policy

| Field | Default | Meaning |
| - | - | - |
| `maxRetries` | 3 | retries after the first attempt (so up to 4 attempts) |
| `initialBackoff` | 100 ms | backoff cap of the first retry |
| `maxBackoff` | 10 s | cap of every backoff |
| `multiplier` | 2 | growth of the cap per retry |
| `maxRetryAfter` | 60 s | longest server-requested `Retry-After` the client waits for |

Backoff for retry *n* (0-based) is **full jitter**: a random wait between 0 and
`min(maxBackoff, initialBackoff × multiplier^n)`.

Requests are retried on HTTP 429, 408, 502, 503, 504 and on network errors. **Idempotent**
requests (`GET HEAD OPTIONS PUT DELETE`, or marked idempotent) are also retried on HTTP 500.
Other requests (for example `POST`) are retried only on 429 and on connection errors that happened
before the request was sent, never after an uncertain send.

On 429 and 503 the client honours `Retry-After` (seconds or HTTP date) and waits
`max(retryAfter, backoff)`. When that wait exceeds `maxRetryAfter` or the remaining
`totalTimeout`, it stops at once with `RATE_LIMITED`/`UNAVAILABLE` and sets `retryAfter` on the
error. Set `maxRetries` to 0 to turn retries off.

## Timeouts and cancellation

- `connectTimeout` bounds connection setup, `requestTimeout` each attempt, `totalTimeout` the whole
  call including backoff sleeps. An exhausted timeout raises `TIMEOUT`.
- Cancellation is honoured during requests and backoff sleeps and raises `CANCELLED`:
  TypeScript `{ signal }` (`AbortSignal`), Rust dropping the future, Go `ctx`, Python `cancel=`
  (`CancelToken`) or task cancellation, Java `…Async` futures (`cancel(true)`).

## TLS and proxies

- Add a private CA with `tls.caCertPath` (or the PEM text in `tls.caCertPem`).
- Mutual TLS needs `tls.clientCertPath` and `tls.clientKeyPath` together.
- `tls.insecureSkipVerify` disables certificate checks. Use it for local tests only; the client
  logs a warning once.
- `HTTP_PROXY`/`HTTPS_PROXY` are **ignored** so that credentials never leave through an unexpected
  proxy. Set `proxy` (or `GROW_GRAYLOG_PROXY`) to use one.
