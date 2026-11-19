# GELF messages and transports

Most applications send logs through a [log client](logging.md), which batches records, redacts
secrets and turns them into GELF messages. The GELF layer underneath is public too, for tools that
want full control over the wire format.

## `GelfMessage`

A GELF 1.1 message: `version` `"1.1"`, `host` (stored as `source`), `short_message` (stored as
`message`), optional `full_message`, `timestamp` (Unix seconds with millisecond precision) and
`level` (syslog 0–7), plus additional fields `_<name>`. Explicit field keys are validated: only
`[A-Za-z0-9_.-]`, never empty and never the reserved `id` (`VALIDATION` otherwise).

Records from the logging API map to GELF the same way in every language:

| Record | GELF |
| - | - |
| severity TRACE, DEBUG / INFO / WARN / ERROR / FATAL | `level` 7 / 6 / 4 / 3 / 2 (reverse: 0–2 → FATAL, 3 → ERROR, 4 → WARN, 5–6 → INFO, 7 → DEBUG) |
| body | `short_message`; a blank body is sent as `"-"` (Graylog drops messages without one) |
| attribute key | `_` + key with every character outside `[A-Za-z0-9_.-]` replaced by `_` (ASCII only); `id` → `_attr_id` |
| string / number value | unchanged |
| boolean | `"true"` / `"false"` (Graylog drops JSON booleans) |
| null | omitted |
| array / object | compact JSON string |
| resource attributes | flattened with their dotted keys (`_service.name`, `_deployment.environment`) |
| trace id / span id / trace flags | `_trace_id`, `_span_id` (lower-case hex), `_trace_flags` (number) |

## Transports

| Transport | Wire | Notes |
| - | - | - |
| `GelfUdpTransport` | one datagram per message; gzip (default), zlib or none; messages larger than the chunk size (default 1420 bytes) are split into GELF chunks (`0x1e 0x0f` + 8-byte id + sequence + count), **at most 128 chunks** (`VALIDATION` above that) | fire-and-forget: delivery is best-effort |
| `GelfTcpTransport` | one persistent connection, each message JSON + one NUL byte; optional TLS (CA, client certificate) | reconnects with backoff after a broken connection (at-least-once: a batch may be delivered twice) |
| `GelfHttpTransport` | `POST <url>` (default `http://<gelfHost>:12202/gelf`), newline-delimited bulk body, gzip by default | **every message ends with `\n`**, also single-message bodies (Graylog 7.0 otherwise drops the first message of later requests on a reused connection). Graylog answers 202 even for invalid messages, so messages are validated client-side. |
| `gelfTransport(protocol)` | — | builds the transport for `udp`, `tcp` or `http` from the client configuration (`gelfHost`, `gelfPort`, `gelfHttpUrl`, `gelfTls`, timeouts, retries) |
| `GelfLogExporter` | — | a `LogExporter` over any GELF transport, for `BatchingLogClient` |

Each transport's `send(messages)` returns `{sent, rejected}`; `close()` releases the socket.

=== "TypeScript"

    ```ts
    import { GelfLevel, GelfMessage, GelfUdpTransport, GraylogClient } from "@grow-codes/graylog";

    const client = GraylogClient.fromEnv();
    const tcp = client.gelfTransport("tcp"); // host/port/TLS from the config
    const message = new GelfMessage({
      host: "checkout-1",
      shortMessage: "payment failed",
      fullMessage: "stack trace…",
      level: GelfLevel.Error,
      fields: { order_id: "o-1", amount: 12.5, retried: true }, // retried → "true"
    });
    console.log(await tcp.send([message])); // { sent: 1, rejected: 0 }
    await tcp.close();

    const udp = new GelfUdpTransport({ host: "graylog", port: 12201, compression: "zlib" });
    await udp.send([message]);
    await udp.close();
    ```

=== "Rust"

    ```rust
    use std::sync::Arc;
    use grow_graylog::{
        GelfLevel, GelfMessage, GelfMessageOptions, GelfProtocol, GelfSendOptions,
        GelfTransportOptions,
    };
    use grow_graylog::logging::attrs;

    let tcp = client.gelf_transport(Some(GelfProtocol::Tcp), GelfTransportOptions::default())?;
    let message = GelfMessage::new(GelfMessageOptions {
        host: "checkout-1".into(),
        short_message: "payment failed".into(),
        level: Some(GelfLevel::Error),
        fields: attrs! { "order_id" => "o-1", "amount" => 12.5 },
        ..Default::default()
    })?;
    let result = tcp.send(&[message], GelfSendOptions::default()).await?;
    println!("sent {}", result.sent);
    tcp.close().await?;
    ```

=== "Go"

    ```go
    tcp, err := client.GelfTransport(graylog.GelfTCP, graylog.GelfTransportOptions{})
    if err != nil {
    	return err
    }
    defer tcp.Close()
    level := graylog.GelfLevelError
    msg, err := graylog.NewGelfMessage(graylog.GelfMessageOptions{
    	Host: "checkout-1", ShortMessage: "payment failed", Level: &level,
    	Fields: map[string]any{"order_id": "o-1", "amount": 12.5},
    })
    res, err := tcp.Send(ctx, []*graylog.GelfMessage{msg}, graylog.GelfSendOptions{})
    fmt.Println(res.Sent, res.Rejected)

    udp, err := graylog.NewGelfUDPTransport(graylog.GelfUDPOptions{Host: "graylog", Port: 12201, Compression: graylog.GelfCompressionZlib})
    ```

=== "Python"

    ```python
    import grow_graylog as sdk

    with sdk.GraylogClient.from_env() as client:
        tcp = client.gelf_transport("tcp")
        message = sdk.GelfMessage(
            "checkout-1",
            "payment failed",
            level=sdk.GelfLevel.ERROR,
            fields={"order_id": "o-1", "amount": 12.5, "retried": True},
        )
        print(tcp.send([message]))  # GelfSendResult(sent=1, rejected=0)
        tcp.close()

        udp = sdk.GelfUdpTransport("graylog", 12201, compression="zlib")
        udp.send([message])
        udp.close()
    ```

=== "Java"

    ```java
    import codes.grow.packages.graylog.*;
    import java.util.List;

    GelfTransport tcp = client.gelfTransport(GelfProtocol.TCP);
    GelfMessage message =
        GelfMessage.builder("checkout-1", "payment failed")
            .level(3)
            .field("order_id", "o-1")
            .field("amount", 12.5)
            .build();
    System.out.println(tcp.send(List.of(message)).sent());
    tcp.close();

    GelfTransport udp = GelfUdpTransport.builder("graylog").port(12201).build();
    udp.send(List.of(message));
    udp.close();
    ```
