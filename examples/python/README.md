# Python examples

Install the package, point it at a running Graylog Open and run an example:

```bash
pip install grow-graylog
export GROW_GRAYLOG_URL=http://127.0.0.1:9000
export GROW_GRAYLOG_API_TOKEN=...   # or GROW_GRAYLOG_USER / GROW_GRAYLOG_PASSWORD
export GROW_GRAYLOG_GELF_HOST=127.0.0.1
python examples/python/basic.py
```

| File | Shows |
| - | - |
| `tour.py` | ensure a GELF input, index sets, streams, send logs through GELF, wait for them, search, get_message |
| `basic.py` | sync client: health, ping, server version, error handling |
| `async_basic.py` | async client, cancellation by task |
| `hooks_and_logging.py` | request hooks, the `grow_graylog` logger, retries and timeouts |
