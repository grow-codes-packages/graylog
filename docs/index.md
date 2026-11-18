# Graylog Open SDK

[![Grow Codes](https://img.shields.io/badge/Grow%20Codes-grow.codes-2ea44f)](https://grow.codes)
[![CI](https://github.com/grow-codes-packages/graylog/actions/workflows/ci.yml/badge.svg)](https://github.com/grow-codes-packages/graylog/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](license.md)

One API for **Graylog Open** in five languages: TypeScript, Rust, Go, Python and Java. Every package
has the same functions, options, defaults, error codes and behaviour, tested against a real
`graylog/graylog:7.0 (+ MongoDB + OpenSearch)` in Docker.

| Language | Package | Coverage |
| - | - | - |
| TypeScript | [`@grow-codes/graylog`](https://www.npmjs.com/package/@grow-codes/graylog) | ![TypeScript coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/graylog/badges/coverage-typescript.json) |
| Rust | [`grow-graylog`](https://crates.io/crates/grow-graylog) | ![Rust coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/graylog/badges/coverage-rust.json) |
| Go | [`github.com/grow-codes-packages/graylog/go`](https://pkg.go.dev/github.com/grow-codes-packages/graylog/go) | ![Go coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/graylog/badges/coverage-go.json) |
| Python | [`grow-graylog`](https://pypi.org/project/grow-graylog/) | ![Python coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/graylog/badges/coverage-python.json) |
| Java | [`codes.grow.packages:graylog`](https://central.sonatype.com/artifact/codes.grow.packages/graylog) | ![Java coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/graylog/badges/coverage-java.json) |

## What you get

- **Client** with health, authenticated ping and server version ([Client](client.md)).
- **Configuration** from code or `GROW_GRAYLOG_*` / vendor environment variables, immutable
  and validated ([Configuration](configuration.md)).
- **Retries** with full-jitter backoff and `Retry-After`, connect/request/total timeouts and
  cancellation in every language.
- **Typed errors** with one set of codes across languages ([Error handling](errors.md)).
- **Redaction everywhere**: credentials never appear in errors, logs, hooks or `toString`
  ([Redaction](redaction.md)).
- **Logging**: batching log client, logger facade, redaction processor, framework adapters and
  log search ([Logging](logging.md)).
- **Service functions** for the Graylog Open API ([Functions](functions.md)).

Start with [Install](install.md) and the [Quickstart](quickstart.md).

!!! note "Independent project"
    This SDK is made by [Grow Codes](https://grow.codes). Graylog Open is a trademark of
    Graylog, Inc.. This project is not affiliated with or endorsed by Graylog, Inc.. See
    [License & disclaimer](license.md).
