# Java examples

Install the package into your local Maven repository, point it at a running Graylog Open and run an
example:

```bash
make -C ../../java pack            # builds and installs codes.grow.packages:graylog
export GROW_GRAYLOG_URL=http://127.0.0.1:9000
export GROW_GRAYLOG_API_TOKEN=...   # or GROW_GRAYLOG_USER / GROW_GRAYLOG_PASSWORD
export GROW_GRAYLOG_GELF_HOST=127.0.0.1   # default: the host of the URL
mvn -q compile exec:java                                                  # BasicExample
mvn -q compile exec:java -Dexec.mainClass=codes.grow.packages.graylog.examples.AsyncExample
mvn -q compile exec:java -Dexec.mainClass=codes.grow.packages.graylog.examples.LoggingExample
```

Against the published package, set `-Dsdk.version=<version>` (or edit `pom.xml`) instead of
installing it locally.

| Class | Shows |
| - | - |
| `BasicExample` | blocking client: health, ping, server version, error handling |
| `AsyncExample` | `…Async` methods, combining futures, cancellation |
| `HooksAndLoggingExample` | request hooks, a logger, retries and timeouts |
| `LoggingExample` | GELF log client, `waitForLog`, a raw GELF message, search and admin listings |
