# grow-graylog (Python)

Python SDK for [Graylog Open](https://grow-codes-packages.github.io/graylog/) by Grow Codes.
Unofficial and community maintained; "Graylog" is a trademark of Graylog, Inc.

```bash
pip install grow-graylog            # REST + GELF (UDP, TCP, HTTP)
pip install "grow-graylog[otlp]"    # + OTLP/gRPC logs exporter (grpcio)
```

```python
from grow_graylog import GraylogClient

# Reads GRAYLOG_URL / GROW_GRAYLOG_URL, GRAYLOG_API_TOKEN (or GRAYLOG_USER + GRAYLOG_PASSWORD),
# GRAYLOG_GELF_HOST, GRAYLOG_GELF_PORT, GRAYLOG_GELF_PROTOCOL ... from the environment.
with GraylogClient.from_env() as client:
    print(client.health(), client.server_version())

    logs = client.log_client(resource={"service.name": "checkout"})  # GELF TCP by default
    logs.logger("api").warn("payment slow", {"order_id": 42, "password": "redacted"})
    logs.flush(10)

    record = client.log_query_client().wait_for_log('service_name:"checkout"', timeout_s=30)
    print(record.severity.name, record.body, dict(record.attributes))
```

The async client has the same methods:

```python
import asyncio
from grow_graylog import AsyncGraylogClient

async def main() -> None:
    async with AsyncGraylogClient.from_env() as client:
        print(await client.health())
        print((await client.search_relative("level:3", 300)).total)

asyncio.run(main())
```

| Module | Functions |
| - | - |
| Client | `health`, `ping`, `server_version`, `system_info`, `close` |
| GELF | `GelfMessage`, `GelfUdpTransport` (gzip/zlib, ≤ 128 chunks), `GelfTcpTransport` (NUL framing, TLS, reconnect), `GelfHttpTransport` (bulk, gzip), `client.gelf_transport()` |
| OTLP | `OtlpGrpcLogExporter`, `client.log_client("otlp")` |
| Logging | `client.log_client()` → `BatchingLogClient` / `Logger`, `client.log_query_client()` → `search`, `tail` (polling, 2 s), `list_streams`, `list_labels`, `wait_for_log` |
| Search | `search(query, range_s= / from_=, to= / keyword=, limit, offset, fields, sort, streams)`, `search_relative(query, seconds)`, `get_message(index, id)`, `list_fields` |
| Admin | `list_inputs`, `get_input`, `get_input_state`, `list_input_types`, `create_input`, `ensure_gelf_input`, `delete_input`, `list_streams`, `get_stream`, `create_stream`, `resume_stream`, `delete_stream`, `list_index_sets` |

- Python 3.10 or newer, typed (`py.typed`), `httpx` based, environment proxies ignored unless
  configured.
- Retries with full-jitter backoff and `Retry-After`, connect/request/total timeouts,
  cancellation (`CancelToken` for sync calls, task cancellation for async), hooks and a
  silent-by-default `logging` logger named `grow_graylog`.
- Credentials are wrapped in `Secret` and never appear in `repr()`, logs or error messages.
- `grow_graylog.testing` ships in-memory fakes and the conformance runner.

Documentation: https://grow-codes-packages.github.io/graylog/ ·
Source: https://github.com/grow-codes-packages/graylog · Licence: Apache-2.0
