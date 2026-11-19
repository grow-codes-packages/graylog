//! Admin REST functions: inputs, streams and index sets.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::client::{decode_json, require_id, seg, GraylogClient};
use crate::config::GelfProtocol;
use crate::core::redact::truncate;
use crate::core::transport::MAX_VENDOR_MESSAGE;
use crate::core::{poll_until, Error, ErrorCode, Method, PollOptions, Result};
use crate::logging::SortOrder;
use crate::models::{
    IndexSet, Input, InputState, Stream, StreamPage, StreamRule, INPUT_STATE_FAILED,
    INPUT_STATE_RUNNING, INPUT_TYPE_GELF_HTTP, INPUT_TYPE_GELF_TCP, INPUT_TYPE_GELF_UDP,
};

const PATH_INPUTS: &str = "/api/system/inputs";
const PATH_INPUT_TYPES: &str = "/api/system/inputs/types";
const PATH_INPUT_STATES: &str = "/api/system/inputstates";
const PATH_STREAMS: &str = "/api/streams";
const PATH_STREAMS_PAGE: &str = "/api/streams/paginated";
const PATH_INDEX_SETS: &str = "/api/system/indices/index_sets";

/// Options of [`GraylogClient::create_input`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateInputOptions {
    /// Title (default `"<class short name> (grow-codes)"`).
    pub title: Option<String>,
    /// Starts the input on one node only; `None` means a global input.
    pub node: Option<String>,
}

/// Options of [`GraylogClient::ensure_gelf_input`]. The default is valid.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EnsureGelfInputOptions {
    /// Title of a newly created input (default `"grow-codes GELF <PROTOCOL> <port>"`).
    pub title: Option<String>,
    /// Bind address of a new input (default `0.0.0.0`); an existing input matches when its bind
    /// address equals this value (or is empty).
    pub bind_address: Option<String>,
    /// Merged over the default configuration of a new input (for example
    /// `{"tls_enable": true}` or `{"enable_bulk_receiving": false}`).
    pub configuration: Map<String, Value>,
    /// Bound on the wait for `RUNNING` (default 30 s).
    pub timeout: Option<Duration>,
    /// Pause between state polls (default 500 ms).
    pub interval: Option<Duration>,
}

/// Result of [`GraylogClient::ensure_gelf_input`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EnsuredInput {
    /// The running input.
    pub input: Input,
    /// Whether this call created it.
    pub created: bool,
}

/// Options of [`GraylogClient::list_streams`]. The default is page 1, 50 per page, sorted by
/// title ascending.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListStreamsOptions {
    /// 1-based page (default 1).
    pub page: Option<u32>,
    /// Page size (default 50).
    pub per_page: Option<u32>,
    /// Filter in Graylog's stream search syntax (for example a title).
    pub query: Option<String>,
    /// Sort field (default `title`).
    pub sort: Option<String>,
    /// Sort order (default ascending).
    pub order: Option<SortOrder>,
}

/// Description of a new stream ([`GraylogClient::create_stream`]). `title` is required.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CreateStreamOptions {
    /// Title.
    pub title: String,
    /// Description.
    pub description: String,
    /// Target index set (default: the default index set, else the first one).
    pub index_set_id: Option<String>,
    /// Routing rules.
    pub rules: Vec<StreamRule>,
    /// `AND` (default: every rule must match) or `OR`.
    pub matching_type: Option<String>,
    /// Whether matches leave the default stream.
    pub remove_matches_from_default_stream: bool,
    /// Keeps the new stream paused (Graylog creates streams paused; `create_stream` resumes them
    /// unless this is set).
    pub disabled: bool,
}

impl CreateStreamOptions {
    /// Options with a title.
    pub fn new(title: impl Into<String>) -> Self {
        CreateStreamOptions {
            title: title.into(),
            ..CreateStreamOptions::default()
        }
    }
    /// Sets the description.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }
    /// Adds a rule.
    pub fn rule(mut self, rule: StreamRule) -> Self {
        self.rules.push(rule);
        self
    }
}

/// Default configuration of a GELF input per protocol (the same as the Docker bootstrap).
pub(crate) fn gelf_input_defaults(
    protocol: GelfProtocol,
) -> Result<(&'static str, Map<String, Value>)> {
    let v = match protocol {
        GelfProtocol::Udp => (
            INPUT_TYPE_GELF_UDP,
            json!({"recv_buffer_size": 262144, "number_worker_threads": 2, "decompress_size_limit": 8388608}),
        ),
        GelfProtocol::Tcp => (
            INPUT_TYPE_GELF_TCP,
            json!({"recv_buffer_size": 1048576, "number_worker_threads": 2, "tls_enable": false,
                "tcp_keepalive": false, "use_null_delimiter": true, "max_message_size": 2097152,
                "decompress_size_limit": 8388608}),
        ),
        GelfProtocol::Http => (
            INPUT_TYPE_GELF_HTTP,
            json!({"recv_buffer_size": 1048576, "number_worker_threads": 2, "tls_enable": false,
                "tcp_keepalive": false, "enable_bulk_receiving": true, "enable_cors": true,
                "max_chunk_size": 8388608, "idle_writer_timeout": 60, "decompress_size_limit": 8388608}),
        ),
        GelfProtocol::Otlp => {
            return Err(Error::validation(
                "ensureGelfInput: protocol must be udp, tcp or http",
            ))
        }
    };
    let Value::Object(map) = v.1 else {
        unreachable!("literal objects")
    };
    Ok((v.0, map))
}

impl GraylogClient {
    /// Every input (`GET /api/system/inputs`).
    pub async fn list_inputs(&self) -> Result<Vec<Input>> {
        #[derive(Deserialize)]
        struct Body {
            #[serde(default)]
            inputs: Option<Vec<Input>>,
        }
        let body: Body = self.get_json(PATH_INPUTS, "listInputs").await?;
        Ok(body.inputs.unwrap_or_default())
    }

    /// One input; `NOT_FOUND` when it does not exist.
    pub async fn get_input(&self, id: &str) -> Result<Input> {
        require_id("getInput", "id", id)?;
        self.get_json(
            &format!("{PATH_INPUTS}/{}", seg(id)),
            &format!("getInput {id}"),
        )
        .await
    }

    /// Installed input types (class → display name).
    pub async fn list_input_types(&self) -> Result<BTreeMap<String, String>> {
        #[derive(Deserialize)]
        struct Body {
            #[serde(default)]
            types: Option<BTreeMap<String, Value>>,
        }
        let body: Body = self.get_json(PATH_INPUT_TYPES, "listInputTypes").await?;
        Ok(body
            .types
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k, v.as_str().unwrap_or_default().to_owned()))
            .collect())
    }

    /// Runtime state of an input; `NOT_FOUND` when it is not running on any node.
    pub async fn get_input_state(&self, id: &str) -> Result<InputState> {
        require_id("getInputState", "id", id)?;
        self.get_json(
            &format!("{PATH_INPUT_STATES}/{}", seg(id)),
            &format!("getInputState {id}"),
        )
        .await
    }

    /// Creates an input of class `input_type` with `configuration` (`POST /api/system/inputs`)
    /// and returns its id. An unknown type is `NOT_FOUND` (Graylog answers 404). Graylog does
    /// not reject a busy port at create time: the input is created and its state becomes
    /// `FAILED` (see [`get_input_state`](Self::get_input_state) or
    /// [`ensure_gelf_input`](Self::ensure_gelf_input)).
    pub async fn create_input(
        &self,
        input_type: &str,
        configuration: Map<String, Value>,
        opts: CreateInputOptions,
    ) -> Result<String> {
        require_id("createInput", "type", input_type)?;
        let title = opts.title.filter(|t| !t.is_empty()).unwrap_or_else(|| {
            let short = input_type.rsplit('.').next().unwrap_or(input_type);
            format!("{short} (grow-codes)")
        });
        let node = opts.node.filter(|n| !n.is_empty());
        let mut body = json!({
            "title": title, "type": input_type, "global": node.is_none(),
            "configuration": configuration,
        });
        if let Some(n) = node {
            body["node"] = json!(n);
        }
        let resp = self
            .send(
                self.request(Method::POST, PATH_INPUTS, "createInput")
                    .json(&body),
            )
            .await?;
        let out: Value = decode_json(&resp, "createInput")?;
        match out.get("id").and_then(Value::as_str) {
            Some(id) if !id.is_empty() => Ok(id.to_owned()),
            _ => Err(Error::unavailable("createInput: response has no input id")),
        }
    }

    /// Deletes an input (`DELETE /api/system/inputs/{id}`); `NOT_FOUND` when it does not exist.
    pub async fn delete_input(&self, id: &str) -> Result<()> {
        require_id("deleteInput", "id", id)?;
        self.send(self.request(
            Method::DELETE,
            &format!("{PATH_INPUTS}/{}", seg(id)),
            &format!("deleteInput {id}"),
        ))
        .await
        .map(|_| ())
    }

    async fn find_gelf_input(
        &self,
        input_type: &str,
        port: u16,
        bind: &str,
    ) -> Result<Option<Input>> {
        Ok(self.list_inputs().await?.into_iter().find(|i| {
            i.input_type == input_type
                && i.port() == port
                && (i.bind_address().is_empty() || i.bind_address() == bind)
        }))
    }

    /// A running GELF input of `protocol` on `port`: an existing input of the same type, port
    /// and bind address is reused, otherwise one is created. It then waits until the input is
    /// `RUNNING`; a `FAILED` input (for example a port already used by another input type) is a
    /// `CONFLICT` error carrying Graylog's message, `TIMEOUT` after `opts.timeout`. An input
    /// created by this call is deleted again when it does not start.
    pub async fn ensure_gelf_input(
        &self,
        protocol: GelfProtocol,
        port: u16,
        opts: EnsureGelfInputOptions,
    ) -> Result<EnsuredInput> {
        const OP: &str = "ensureGelfInput";
        let (input_type, mut config) = gelf_input_defaults(protocol)?;
        if port == 0 {
            return Err(Error::validation(format!(
                "{OP}: port must be an integer 1..65535"
            )));
        }
        let bind = opts
            .bind_address
            .clone()
            .filter(|b| !b.is_empty())
            .unwrap_or_else(|| "0.0.0.0".to_owned());
        let mut created = false;
        let input = match self.find_gelf_input(input_type, port, &bind).await? {
            Some(i) => i,
            None => {
                config.extend(opts.configuration.clone());
                config.insert("bind_address".into(), json!(bind));
                config.insert("port".into(), json!(port));
                let title = opts
                    .title
                    .clone()
                    .filter(|t| !t.is_empty())
                    .unwrap_or_else(|| {
                        format!(
                            "grow-codes GELF {} {port}",
                            protocol.as_str().to_ascii_uppercase()
                        )
                    });
                let create = CreateInputOptions {
                    title: Some(title),
                    node: None,
                };
                match self.create_input(input_type, config, create).await {
                    Ok(id) => {
                        created = true;
                        self.get_input(&id).await?
                    }
                    Err(err) => {
                        // The create may have reached the server; re-list before failing.
                        match self.find_gelf_input(input_type, port, &bind).await {
                            Ok(Some(i)) => i,
                            _ => return Err(err),
                        }
                    }
                }
            }
        };
        let poll = PollOptions {
            timeout: opts.timeout.unwrap_or(Duration::from_secs(30)),
            interval: opts.interval.unwrap_or(Duration::from_millis(500)),
        };
        let id = input.id.clone();
        let waited = poll_until(OP, poll, || async {
            match self.get_input_state(&id).await {
                Err(e) if e.code() == ErrorCode::NotFound => Ok(None),
                Err(e) => Err(e),
                Ok(st) if st.state == INPUT_STATE_FAILED => {
                    let mut msg = format!("{OP} {protocol}:{port}: input failed to start");
                    if !st.detailed_message.is_empty() {
                        msg.push_str(": ");
                        msg.push_str(&truncate(
                            &self.transport().redact(&st.detailed_message),
                            MAX_VENDOR_MESSAGE,
                        ));
                    }
                    Err(Error::conflict(msg))
                }
                Ok(st) => Ok((st.state == INPUT_STATE_RUNNING).then_some(())),
            }
        })
        .await;
        if let Err(err) = waited {
            if created && err.code() != ErrorCode::Cancelled {
                let _ = self.delete_input(&id).await;
            }
            return Err(err);
        }
        Ok(EnsuredInput { input, created })
    }

    /// One page of streams (`GET /api/streams/paginated`).
    pub async fn list_streams(&self, opts: ListStreamsOptions) -> Result<StreamPage> {
        #[derive(Deserialize, Default)]
        struct Pagination {
            #[serde(default)]
            total: u64,
            #[serde(default)]
            page: u32,
            #[serde(default)]
            per_page: u32,
        }
        #[derive(Deserialize)]
        struct Body {
            #[serde(default)]
            pagination: Option<Pagination>,
            #[serde(default)]
            elements: Option<Vec<Stream>>,
        }
        let order = match opts.order.unwrap_or(SortOrder::Asc) {
            SortOrder::Asc => "asc",
            SortOrder::Desc => "desc",
        };
        let mut req = self
            .request(Method::GET, PATH_STREAMS_PAGE, "listStreams")
            .query(
                "page",
                opts.page.filter(|p| *p > 0).unwrap_or(1).to_string(),
            )
            .query(
                "per_page",
                opts.per_page.filter(|p| *p > 0).unwrap_or(50).to_string(),
            )
            .query(
                "sort",
                opts.sort
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "title".into()),
            )
            .query("order", order);
        if let Some(q) = opts.query.filter(|q| !q.is_empty()) {
            req = req.query("query", q);
        }
        let resp = self.send(req).await?;
        let body: Body = decode_json(&resp, "listStreams")?;
        let pagination = body.pagination.unwrap_or_default();
        Ok(StreamPage {
            streams: body.elements.unwrap_or_default(),
            total: pagination.total,
            page: pagination.page,
            per_page: pagination.per_page,
        })
    }

    /// Follows [`list_streams`](Self::list_streams) pages and returns every stream.
    pub(crate) async fn list_all_streams(&self) -> Result<Vec<Stream>> {
        let mut out = Vec::new();
        let mut page = 1;
        loop {
            let p = self
                .list_streams(ListStreamsOptions {
                    page: Some(page),
                    per_page: Some(100),
                    ..ListStreamsOptions::default()
                })
                .await?;
            let empty = p.streams.is_empty();
            out.extend(p.streams);
            if empty || out.len() as u64 >= p.total {
                return Ok(out);
            }
            page += 1;
        }
    }

    /// One stream; `NOT_FOUND` when it does not exist.
    pub async fn get_stream(&self, id: &str) -> Result<Stream> {
        require_id("getStream", "id", id)?;
        self.get_json(
            &format!("{PATH_STREAMS}/{}", seg(id)),
            &format!("getStream {id}"),
        )
        .await
    }

    /// Creates a stream (`POST /api/streams`) and, unless `opts.disabled`, resumes it so it
    /// starts routing messages. Returns the stream id.
    pub async fn create_stream(&self, opts: CreateStreamOptions) -> Result<String> {
        const OP: &str = "createStream";
        if opts.title.trim().is_empty() {
            return Err(Error::validation(format!("{OP}: title is required")));
        }
        let matching = opts
            .matching_type
            .as_deref()
            .filter(|m| !m.is_empty())
            .unwrap_or("AND")
            .to_ascii_uppercase();
        if matching != "AND" && matching != "OR" {
            return Err(Error::validation(format!(
                "{OP}: matchingType must be \"AND\" or \"OR\""
            )));
        }
        let index_set_id = match opts.index_set_id.filter(|s| !s.is_empty()) {
            Some(id) => id,
            None => {
                let sets = self.list_index_sets().await?;
                sets.iter()
                    .find(|s| s.default)
                    .or(sets.first())
                    .map(|s| s.id.clone())
                    .ok_or_else(|| Error::validation(format!("{OP}: no index set available")))?
            }
        };
        let entity = json!({
            "title": opts.title, "description": opts.description, "index_set_id": index_set_id,
            "matching_type": matching,
            "remove_matches_from_default_stream": opts.remove_matches_from_default_stream,
            "rules": opts.rules,
        });
        let resp = self
            .send(
                self.request(Method::POST, PATH_STREAMS, OP)
                    .json(&json!({ "entity": entity })),
            )
            .await?;
        let out: Value = decode_json(&resp, OP)?;
        let id = match out.get("stream_id").and_then(Value::as_str) {
            Some(id) if !id.is_empty() => id.to_owned(),
            _ => {
                return Err(Error::unavailable(format!(
                    "{OP}: response has no stream id"
                )))
            }
        };
        if !opts.disabled {
            self.resume_stream(&id).await?;
        }
        Ok(id)
    }

    /// Starts a paused stream (`POST /api/streams/{id}/resume`).
    pub async fn resume_stream(&self, id: &str) -> Result<()> {
        require_id("resumeStream", "id", id)?;
        self.send(
            self.request(
                Method::POST,
                &format!("{PATH_STREAMS}/{}/resume", seg(id)),
                &format!("resumeStream {id}"),
            )
            .idempotent(true),
        )
        .await
        .map(|_| ())
    }

    /// Deletes a stream (`DELETE /api/streams/{id}`); `NOT_FOUND` when it does not exist.
    pub async fn delete_stream(&self, id: &str) -> Result<()> {
        require_id("deleteStream", "id", id)?;
        self.send(self.request(
            Method::DELETE,
            &format!("{PATH_STREAMS}/{}", seg(id)),
            &format!("deleteStream {id}"),
        ))
        .await
        .map(|_| ())
    }

    /// Every index set (`GET /api/system/indices/index_sets?skip_stats=true`).
    pub async fn list_index_sets(&self) -> Result<Vec<IndexSet>> {
        #[derive(Deserialize)]
        struct Body {
            #[serde(default)]
            index_sets: Option<Vec<IndexSet>>,
        }
        let resp = self
            .send(
                self.request(Method::GET, PATH_INDEX_SETS, "listIndexSets")
                    .query("skip_stats", "true"),
            )
            .await?;
        let body: Body = decode_json(&resp, "listIndexSets")?;
        Ok(body.index_sets.unwrap_or_default())
    }
}
