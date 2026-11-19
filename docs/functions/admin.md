# Admin: inputs, streams, index sets

REST administration of the objects a logging setup needs. Every call needs credentials with the
matching Graylog permissions (`PERMISSION_DENIED` otherwise).

## Inputs

| Function | Graylog API | Result |
| - | - | - |
| `listInputs()` | `GET /api/system/inputs` | every input (`id`, `title`, `type`, `name`, `global`, `node`, `createdAt`, `attributes`, …). Secret attributes come back as `{"is_set": …}` objects, never as text. |
| `getInput(id)` | `GET /api/system/inputs/{id}` | one input; `NOT_FOUND` when it is gone |
| `listInputTypes()` | `GET /api/system/inputs/types` | map class name → display name |
| `getInputState(id)` | `GET /api/system/inputstates/{id}` | `state` (`RUNNING`, `STARTING`, `FAILED`, …), `startedAt`, `detailedMessage` |
| `createInput(type, config, {title, global = true, node})` | `POST /api/system/inputs` | the new input id. An unknown type is `NOT_FOUND` (Graylog answers 404, not 400). A busy port is **not** rejected here: the input is created and its state becomes `FAILED`. |
| `ensureGelfInput(protocol, port, {title, bindAddress = 0.0.0.0, configuration, timeout = 30 s, interval = 0.5 s})` | list, match type + port (+ bind address), else create; then poll the state | the running input plus `created`. Waits until `RUNNING`; `FAILED` (e.g. port in use) → `CONFLICT` and an input this call created is deleted again; not running within `timeout` → `TIMEOUT`. GELF TCP inputs use NUL framing, GELF HTTP inputs get bulk receiving on. |
| `deleteInput(id)` | `DELETE /api/system/inputs/{id}` | nothing; `NOT_FOUND` when it is gone |

The GELF input classes are exported as constants: TypeScript `GELF_INPUT_TYPES`, Rust
`INPUT_TYPE_GELF_UDP|TCP|HTTP`, Go `InputTypeGelfUDP|TCP|HTTP`, Python `GELF_INPUT_TYPES`, Java
`InputTypes.GELF_UDP|TCP|HTTP` (plus the OTLP gRPC input class).

=== "TypeScript"

    ```ts
    import { GELF_INPUT_TYPES, GraylogClient } from "@grow-codes/graylog";

    const client = GraylogClient.fromEnv();
    const input = await client.ensureGelfInput("tcp", 12201); // reused or created, RUNNING
    console.log(input.id, input.created);
    console.log((await client.listInputs()).map((i) => `${i.title} ${i.type}`));
    console.log((await client.getInputState(input.id)).state); // "RUNNING"

    const id = await client.createInput(
      GELF_INPUT_TYPES.udp,
      { bind_address: "0.0.0.0", port: 12301, recv_buffer_size: 262144 },
      { title: "app UDP" },
    );
    console.log((await client.getInput(id)).attributes.port);
    await client.deleteInput(id);
    ```

=== "Rust"

    ```rust
    use grow_graylog::{
        CreateInputOptions, EnsureGelfInputOptions, GelfProtocol, INPUT_TYPE_GELF_UDP,
    };
    use serde_json::json;

    let input = client
        .ensure_gelf_input(GelfProtocol::Tcp, 12201, EnsureGelfInputOptions::default())
        .await?;
    println!("{} created={}", input.input.id, input.created);
    println!("{:?}", client.get_input_state(&input.input.id).await?.state);

    let config = json!({"bind_address": "0.0.0.0", "port": 12301});
    let id = client
        .create_input(
            INPUT_TYPE_GELF_UDP,
            config.as_object().unwrap().clone(),
            CreateInputOptions { title: Some("app UDP".into()), ..Default::default() },
        )
        .await?;
    println!("{}", client.list_inputs().await?.len());
    client.delete_input(&id).await?;
    ```

=== "Go"

    ```go
    input, err := client.EnsureGelfInput(ctx, graylog.GelfTCP, 12201, graylog.EnsureGelfInputOptions{})
    if errors.Is(err, graylog.ErrConflict) {
    	return fmt.Errorf("port in use: %w", err)
    }
    fmt.Println(input.ID, input.Created)

    id, err := client.CreateInput(ctx, graylog.InputTypeGelfUDP,
    	map[string]any{"bind_address": "0.0.0.0", "port": 12301},
    	graylog.CreateInputOptions{Title: "app UDP"})
    state, err := client.GetInputState(ctx, id)
    fmt.Println(state.State)
    inputs, err := client.ListInputs(ctx)
    err = client.DeleteInput(ctx, id)
    ```

=== "Python"

    ```python
    import grow_graylog as sdk

    with sdk.GraylogClient.from_env() as client:
        inp = client.ensure_gelf_input("tcp", 12201, timeout_s=30)
        print(inp.id, inp.created)
        print(client.get_input_state(inp.id).state)  # "RUNNING"

        input_id = client.create_input(
            sdk.GELF_INPUT_TYPES["udp"],
            {"bind_address": "0.0.0.0", "port": 12301},
            title="app UDP",
        )
        print([i.title for i in client.list_inputs()], client.list_input_types())
        client.delete_input(input_id)
    ```

=== "Java"

    ```java
    import codes.grow.packages.graylog.*;
    import java.util.Map;

    EnsuredInput input =
        client.ensureGelfInput(GelfProtocol.TCP, 12201, EnsureGelfInputOptions.defaults());
    System.out.println(input.id() + " created=" + input.created());
    System.out.println(client.getInputState(input.id()).state());

    String id =
        client.createInput(
            InputTypes.GELF_UDP,
            Map.of("bind_address", "0.0.0.0", "port", 12301),
            CreateInputOptions.titled("app UDP"));
    System.out.println(client.listInputs().size());
    client.deleteInput(id);
    ```

## Streams and index sets

| Function | Graylog API | Result |
| - | - | - |
| `listStreams({page = 1, perPage = 50, query, sort = "title", order = "asc"})` | `GET /api/streams/paginated` | one page: `streams`, `total`, `page`, `perPage` (1-based pages). Built-in streams: `Default Stream`, `All events`, `All system events`. |
| `getStream(id)` | `GET /api/streams/{id}` | `id`, `title`, `description`, `disabled`, `indexSetId`, `isDefault`, `matchingType`, `rules`, … |
| `createStream({title, description, indexSetId, rules, matchingType = "AND", removeMatchesFromDefaultStream = false, start = true})` | `POST /api/streams` (`{"entity": …}` envelope) then `POST /api/streams/{id}/resume` | the new stream id. Graylog creates streams **paused**; the SDK resumes it unless `start` is false. `indexSetId` defaults to the default index set. |
| `resumeStream(id)` | `POST /api/streams/{id}/resume` | nothing |
| `deleteStream(id)` | `DELETE /api/streams/{id}` | nothing; `NOT_FOUND` when it is gone |
| `listIndexSets()` | `GET /api/system/indices/index_sets?skip_stats=true` | every index set; the default one has `isDefault` (`Default` in Go) |

Stream rule types: 1 exact, 2 regex, 3 greater than, 4 smaller than, 5 field presence, 6 contains,
7 always match, 8 match input (Go `StreamRuleExact`…, Java `StreamRule.TYPE_EXACT`…, Rust
`StreamRule::exact`).

=== "TypeScript"

    ```ts
    const streamId = await client.createStream({
      title: "checkout errors",
      rules: [{ field: "service_name", type: 1, value: "checkout", inverted: false, description: "" }],
    });
    const stream = await client.getStream(streamId);
    console.log(stream.disabled); // false: the SDK resumed it
    const page = await client.listStreams({ perPage: 100, query: "checkout" });
    console.log(page.total, page.streams.map((s) => s.title));
    const sets = await client.listIndexSets();
    console.log(sets.find((s) => s.isDefault)?.title);
    await client.deleteStream(streamId);
    ```

=== "Rust"

    ```rust
    use grow_graylog::{CreateStreamOptions, ListStreamsOptions, StreamRule};

    let stream_id = client
        .create_stream(
            CreateStreamOptions::new("checkout errors")
                .rule(StreamRule::exact("service_name", "checkout")),
        )
        .await?;
    assert!(!client.get_stream(&stream_id).await?.disabled);
    let page = client.list_streams(ListStreamsOptions::default()).await?;
    println!("{} streams", page.total);
    let sets = client.list_index_sets().await?;
    println!("{:?}", sets.iter().find(|s| s.is_default).map(|s| &s.title));
    client.delete_stream(&stream_id).await?;
    ```

=== "Go"

    ```go
    streamID, err := client.CreateStream(ctx, graylog.CreateStreamOptions{
    	Title: "checkout errors",
    	Rules: []graylog.StreamRule{{Field: "service_name", Type: graylog.StreamRuleExact, Value: "checkout"}},
    })
    stream, err := client.GetStream(ctx, streamID)
    page, err := client.ListStreams(ctx, graylog.ListStreamsOptions{PerPage: 100})
    sets, err := client.ListIndexSets(ctx)
    fmt.Println(stream.Disabled, page.Total, len(sets))
    defer client.DeleteStream(context.Background(), streamID)
    ```

=== "Python"

    ```python
    stream_id = client.create_stream(
        "checkout errors",
        rules=[sdk.StreamRule("service_name", 1, "checkout")],
    )
    assert not client.get_stream(stream_id).disabled
    page = client.list_streams(per_page=100, query="checkout")
    print(page.total, [s.title for s in page.streams])
    default = next(s for s in client.list_index_sets() if s.is_default)
    client.delete_stream(stream_id)
    ```

=== "Java"

    ```java
    String streamId =
        client.createStream(
            CreateStreamOptions.builder("checkout errors")
                .rules(StreamRule.of("service_name", StreamRule.TYPE_EXACT, "checkout"))
                .build());
    System.out.println(client.getStream(streamId).disabled());
    StreamPage page = client.listStreams(ListStreamsOptions.page(1, 100).withQuery("checkout"));
    System.out.println(page.total());
    client.listIndexSets().stream().filter(IndexSet::isDefault).findFirst().ifPresent(System.out::println);
    client.deleteStream(streamId);
    ```
