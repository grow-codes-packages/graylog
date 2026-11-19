# Search

Search uses Graylog's synchronous Views search (`POST /api/views/search/sync`) with a Lucene
`query_string`: `"exact phrase"`, `marker:abc`, `message:foo*`, `level:<=3`, `_exists_:trace_id`,
`trace_id:4bf92f…` (GELF records written by this SDK) or `otel_trace_id:4bf92f…` (OTLP records).
Messages become searchable about 1–2 s after ingest.

| Function | Result |
| - | - |
| `search(query, {range \| from+to \| keyword, limit = 100, offset = 0, fields, sort, streams})` | one page: `messages` (`id`, `index`, `timestamp`, `fields`), `total` (all matches in the range), resolved `from`/`to`, `nextOffset` while more matches exist. Give at most one time range: `range` (relative seconds; **default 300 s**), `from`/`to` (absolute; `from` defaults to `to` − 300 s, `to` to now) or `keyword` (`"last five minutes"`). `sort` defaults to `timestamp` descending. `fields` limits the returned fields (Graylog always adds `_id`). `streams` limits the search to stream ids (default: every stream the caller may read). |
| `searchRelative(query, seconds, opts)` | the same with a relative range |
| `getMessage(index, id)` | one stored message (`GET /api/messages/{index}/{id}`); `index` and `id` come from a search hit; `NOT_FOUND` when it is gone |
| `logRecordFromMessage(fields)` | a normalized `LogRecord` from stored fields (below); also `message.record()` / `result.records()` where the language has them |

Query errors: Graylog answers **HTTP 200** for an invalid Lucene query, with `errors[]` in the
body; the SDK raises `VALIDATION` with Graylog's description. A malformed request is a 400
(`VALIDATION`), missing credentials 401 (`AUTHENTICATION`).

**Read-back mapping** (identical in all five languages): Graylog stores `.` in field names as `_`,
so `service_name`, `service_version`, `service_namespace`, `service_instance_id` and
`deployment_environment(_name)` map back to the dotted resource keys; `source` becomes
`resource["host.name"]`; `level` (syslog) becomes the severity; `trace_id`/`span_id`/`trace_flags`
fill the trace fields; `attr_id` becomes the attribute `id`; other non-`gl2_*` fields become
attributes. OTLP-ingested records (`otel_*` fields) are preferred when present.

=== "TypeScript"

    ```ts
    const page = await client.search("marker:abc AND level:<=3", {
      range: 600,
      limit: 50,
      fields: ["message", "source", "timestamp"],
      sort: { field: "timestamp", order: "asc" },
    });
    console.log(page.total, page.nextOffset);
    for (const m of page.messages) console.log(m.timestamp, m.fields.message);

    const recent = await client.searchRelative("checkout", 60, { streams: [streamId] });
    const first = recent.messages[0];
    if (first) {
      const msg = await client.getMessage(first.index, first.id);
      const record = logRecordFromMessage(msg.fields); // severity, body, resource, attributes
    }
    ```

=== "Rust"

    ```rust
    use std::time::{Duration, SystemTime};
    use grow_graylog::{MessageSearchOptions, SearchSort};

    let page = client
        .search(
            "marker:abc",
            MessageSearchOptions {
                start: Some(SystemTime::now() - Duration::from_secs(600)),
                limit: Some(50),
                sort: vec![SearchSort::asc("timestamp")],
                ..Default::default()
            },
        )
        .await?;
    println!("{} matches", page.total);
    for m in &page.messages {
        println!("{:?} {}", m.timestamp, m.record().body);
    }
    let recent = client
        .search_relative("checkout", Duration::from_secs(60), MessageSearchOptions::default())
        .await?;
    if let Some(m) = recent.messages.first() {
        let msg = client.get_message(&m.index, &m.id).await?;
        println!("{:?}", msg.fields.get("source"));
    }
    ```

=== "Go"

    ```go
    res, err := client.Search(ctx, "marker:abc", graylog.MessageSearchOptions{
    	Range:  10 * time.Minute,
    	Limit:  50,
    	Fields: []string{"message", "source"},
    	Sort:   []graylog.SearchSort{{Field: "timestamp", Order: graylog.OrderAsc}},
    })
    if errors.Is(err, graylog.ErrValidation) {
    	return fmt.Errorf("bad query: %w", err)
    }
    fmt.Println(res.Total, res.NextOffset)
    for _, rec := range res.Records() {
    	fmt.Println(rec.SeverityText, rec.Body)
    }
    recent, err := client.SearchRelative(ctx, "checkout", time.Minute, graylog.MessageSearchOptions{})
    if len(recent.Messages) > 0 {
    	m, err := client.GetMessage(ctx, recent.Messages[0].Index, recent.Messages[0].ID)
    	fmt.Println(m.Fields["source"], err)
    }
    ```

=== "Python"

    ```python
    page = client.search(
        "marker:abc",
        range_s=600,
        limit=50,
        fields=["message", "source"],
        sort=sdk.SearchSort("timestamp", "asc"),
    )
    print(page.total, page.next_offset)
    for m in page.messages:
        print(m.timestamp, m.fields["message"])

    recent = client.search_relative("checkout", 60, streams=[stream_id])
    if recent.messages:
        first = recent.messages[0]
        msg = client.get_message(first.index, first.id)
        record = sdk.log_record_from_message(msg.fields)
    ```

=== "Java"

    ```java
    import java.time.Duration;

    MessageSearchResult page =
        client.search(
            "marker:abc",
            MessageSearchOptions.builder()
                .range(Duration.ofMinutes(10))
                .limit(50)
                .fields("message", "source")
                .sort(SearchSort.asc("timestamp"))
                .build());
    System.out.println(page.total());
    page.records().forEach(r -> System.out.println(r.severity() + " " + r.body()));

    MessageSearchResult recent = client.searchRelative("checkout", Duration.ofMinutes(1));
    if (!recent.messages().isEmpty()) {
      GraylogMessage first = recent.messages().get(0);
      GraylogMessage msg = client.getMessage(first.index(), first.id());
      System.out.println(msg.fields().get("source"));
    }
    ```
