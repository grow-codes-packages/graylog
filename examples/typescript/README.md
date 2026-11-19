# TypeScript example

A tour of `@grow-codes/graylog`: health, version, admin (GELF input, index sets, streams), sending
logs over GELF and reading them back with search.

```sh
(cd ../../typescript && npm install && npm run build)
npm install
GRAYLOG_URL=http://127.0.0.1:9000 GRAYLOG_API_TOKEN=... GRAYLOG_GELF_HOST=127.0.0.1 npm start
```

`GRAYLOG_GELF_PROTOCOL` (`tcp` default, `udp`, `http`) and `GRAYLOG_GELF_PORT` select the GELF input;
the example creates it when it does not exist (needs an admin token).

Replace the `file:` dependency in `package.json` with a version (`npm install @grow-codes/graylog`)
to run it against the published package.
