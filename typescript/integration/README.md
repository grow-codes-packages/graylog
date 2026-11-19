# TypeScript integration tests

A consumer project: it installs the packed `@grow-codes/graylog` tarball (never the source tree)
and runs the integration and conformance tests with `node --test` against a real Graylog Open.

```sh
cd typescript && make pack            # writes dist/grow-codes-graylog-<version>.tgz
cd integration && npm run install-package
GROW_GRAYLOG_URL=http://127.0.0.1:9000 GROW_GRAYLOG_API_TOKEN=... GRAYLOG_GELF_HOST=127.0.0.1 npm test
```

In CI and locally with Docker this runs inside `docker/Dockerfile.typescript`
(`make test-docker LANGS=typescript` from the repository root), which reads `/bootstrap/env`.
