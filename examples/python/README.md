# Python examples

Install the package, point it at a running Graylog Open and run an example:

```bash
pip install grow-graylog
export GROW_GRAYLOG_URL=http://127.0.0.1:9000
export GROW_GRAYLOG_TOKEN=...   # when the service needs one
python examples/python/basic.py
```

| File | Shows |
| - | - |
| `basic.py` | sync client: health, ping, server version, error handling |
| `async_basic.py` | async client, cancellation by task |
| `hooks_and_logging.py` | request hooks, the `grow_graylog` logger, retries and timeouts |
