# grow-graylog (Python)

Python SDK for [Graylog Open](https://grow-codes-packages.github.io/graylog/) by Grow Codes.
Unofficial and community maintained; "Graylog Open" is a trademark of Graylog, Inc..

```bash
pip install grow-graylog
```

```python
from grow_graylog import GraylogClient, GraylogConfig

# Reads GROW_GRAYLOG_URL, GROW_GRAYLOG_TOKEN, ... from the environment.
with GraylogClient.from_env() as client:
    print(client.health())
    print(client.server_version())
```

The async client has the same methods:

```python
import asyncio
from grow_graylog import AsyncGraylogClient

async def main() -> None:
    async with AsyncGraylogClient.from_env() as client:
        print(await client.health())

asyncio.run(main())
```

- Python 3.10 or newer, typed (`py.typed`), `httpx` based, environment proxies ignored unless
  configured.
- Retries with full-jitter backoff and `Retry-After`, connect/request/total timeouts,
  cancellation, hooks and a silent-by-default `logging` logger named `grow_graylog`.
- Credentials are wrapped in `Secret` and never appear in `repr()`, logs or error messages.
- `grow_graylog.testing` ships in-memory fakes and the conformance runner.

Documentation: https://grow-codes-packages.github.io/graylog/ ·
Source: https://github.com/grow-codes-packages/graylog · Licence: Apache-2.0
