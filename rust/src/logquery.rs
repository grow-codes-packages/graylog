//! `LogQueryClient` of the logging category on top of Graylog's Views search API.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use crate::client::GraylogClient;
use crate::core::{Error, Result};
use crate::logging::{
    LogQueryClient, LogRecord, LogSearchResult, RecordCallback, SearchOptions, SortOrder,
    TailHandle, TailOptions, WaitOptions,
};
use crate::search::{
    MessageSearchOptions, SearchSort, DEFAULT_MESSAGE_SORT_FIELD, MAX_SEARCH_LIMIT,
};

/// Poll interval of [`LogQuery`]'s `tail` when the options keep the template default (2 s).
pub const DEFAULT_TAIL_INTERVAL: Duration = Duration::from_secs(2);
/// Search window of [`LogQuery`]'s `search` when no start is given (1 h).
pub const DEFAULT_LOG_QUERY_WINDOW: Duration = Duration::from_secs(3600);
/// How far back each tail poll looks before the newest record seen, so records that become
/// searchable late (ingest takes 1–2 s) are not missed; duplicates are removed by message id.
const TAIL_OVERLAP: Duration = Duration::from_secs(10);

/// Options of [`GraylogClient::log_query`]. The default is valid.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogQueryOptions {
    /// Limits every search to these stream ids (default: every readable stream).
    pub streams: Vec<String>,
    /// Search window when `SearchOptions::start` is unset: end minus this (default 1 h).
    pub default_window: Option<Duration>,
}

/// The `LogQueryClient` of this SDK. Queries use Graylog's Lucene syntax (`marker:abc`,
/// `"exact phrase"`, `level:<=3`, `trace_id:4bf9…`).
#[derive(Debug, Clone)]
pub struct LogQuery {
    client: GraylogClient,
    streams: Vec<String>,
    window: Duration,
}

impl GraylogClient {
    /// The `LogQueryClient` of this client.
    pub fn log_query(&self, opts: LogQueryOptions) -> LogQuery {
        LogQuery {
            client: self.clone(),
            streams: opts.streams,
            window: opts
                .default_window
                .filter(|w| !w.is_zero())
                .unwrap_or(DEFAULT_LOG_QUERY_WINDOW),
        }
    }
}

fn sorts(order: SortOrder) -> Vec<SearchSort> {
    vec![
        SearchSort {
            field: DEFAULT_MESSAGE_SORT_FIELD.into(),
            order,
        },
        SearchSort {
            field: "gl2_message_id".into(),
            order,
        },
    ]
}

#[async_trait]
impl LogQueryClient for LogQuery {
    /// Normalized records (see [`log_record_from_message`](crate::log_record_from_message))
    /// matching `query` between `opts.start` and `opts.end` (defaults: end = now, start = end −
    /// the default window), newest first by default, ties broken by `gl2_message_id`. The cursor
    /// is the offset of the next page; `next_cursor` is set while more matches exist and `total`
    /// is Graylog's match count.
    async fn search(&self, query: &str, opts: SearchOptions) -> Result<LogSearchResult> {
        let offset = match &opts.cursor {
            Some(c) => c
                .parse::<usize>()
                .map_err(|_| Error::validation("logs.search: invalid cursor"))?,
            None => 0,
        };
        let end = opts.end.unwrap_or_else(SystemTime::now);
        let start = opts.start.unwrap_or_else(|| {
            end.checked_sub(self.window)
                .unwrap_or(SystemTime::UNIX_EPOCH)
        });
        let res = self
            .client
            .search(
                query,
                MessageSearchOptions {
                    start: Some(start),
                    end: Some(end),
                    limit: Some(opts.limit.clamp(1, MAX_SEARCH_LIMIT)),
                    offset,
                    streams: self.streams.clone(),
                    sort: sorts(opts.order),
                    ..MessageSearchOptions::default()
                },
            )
            .await?;
        Ok(LogSearchResult {
            records: res.records(),
            next_cursor: res.next_offset.map(|n| n.to_string()),
            total: Some(res.total),
        })
    }

    /// Polls `search` every `opts.interval` (2 s when the template default of 1 s is kept;
    /// Graylog has no streaming API) and calls `on_record` once per new matching record, oldest
    /// first, starting at `opts.start` (default now). Each poll looks back 10 s before the
    /// newest record seen and drops duplicates by message id, so late records are delivered
    /// too. Search errors are logged and polling continues. The tail stops with the handle or
    /// when the client is closed.
    async fn tail(
        &self,
        query: &str,
        on_record: RecordCallback,
        opts: TailOptions,
    ) -> Result<TailHandle> {
        if self.client.is_closed() {
            return Err(Error::cancelled("logs.tail: client is closed"));
        }
        let interval =
            if opts.interval == TailOptions::default().interval || opts.interval.is_zero() {
                DEFAULT_TAIL_INTERVAL
            } else {
                opts.interval
            };
        let handle = TailHandle::new();
        let stopper = handle.clone();
        self.client.on_close(move || {
            Box::pin(async move {
                stopper.stop();
            })
        });
        let mut tailer = Tailer {
            q: self.clone(),
            query: query.to_owned(),
            since: opts.start.unwrap_or_else(SystemTime::now),
            newest: None,
            seen: HashMap::new(),
        };
        let h = handle.clone();
        tokio::spawn(async move {
            while !h.is_stopped() {
                tailer.poll(&h, &on_record).await;
                tokio::select! {
                    _ = h.stopped() => break,
                    _ = tokio::time::sleep(interval) => {}
                }
            }
        });
        Ok(handle)
    }

    /// Titles of every stream (all pages, sorted).
    async fn list_streams(&self) -> Result<Vec<String>> {
        let mut out: Vec<String> = self
            .client
            .list_all_streams()
            .await?
            .into_iter()
            .map(|s| s.title)
            .collect();
        out.sort();
        Ok(out)
    }

    /// Every indexed field name (`GET /api/system/fields`), sorted.
    async fn list_labels(&self) -> Result<Vec<String>> {
        self.client.list_fields().await
    }

    /// Polls `search` until a record matches (see [`wait_for_log`](crate::logging::wait_for_log)).
    async fn wait_for_log(&self, query: &str, opts: WaitOptions) -> Result<LogRecord> {
        crate::logging::wait_for_log(self, query, opts).await
    }
}

struct Tailer {
    q: LogQuery,
    query: String,
    since: SystemTime,
    newest: Option<SystemTime>,
    seen: HashMap<String, SystemTime>,
}

impl Tailer {
    async fn poll(&mut self, h: &TailHandle, on_record: &RecordCallback) {
        let mut from = self.since;
        if let Some(n) = self.newest.and_then(|n| n.checked_sub(TAIL_OVERLAP)) {
            if n > from {
                from = n;
            }
        }
        let mut offset = 0;
        loop {
            let res = self
                .q
                .client
                .search(
                    &self.query,
                    MessageSearchOptions {
                        start: Some(from),
                        end: Some(SystemTime::now() + Duration::from_secs(60)),
                        limit: Some(1000),
                        offset,
                        streams: self.q.streams.clone(),
                        sort: sorts(SortOrder::Asc),
                        ..MessageSearchOptions::default()
                    },
                )
                .await;
            let res = match res {
                Ok(r) => r,
                Err(e) => {
                    if !h.is_stopped() {
                        ::tracing::warn!(target: "grow_graylog::tail", error = %e, "logs.tail: search failed");
                    }
                    return;
                }
            };
            for m in &res.messages {
                if h.is_stopped() {
                    return;
                }
                if !m.id.is_empty() && self.seen.contains_key(&m.id) {
                    continue;
                }
                let ts = m.timestamp.unwrap_or(self.since);
                self.seen.insert(m.id.clone(), ts);
                if self.newest.is_none_or(|n| ts > n) {
                    self.newest = Some(ts);
                }
                let cb = on_record.clone();
                let rec = m.record();
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cb(rec)));
            }
            offset += res.messages.len();
            if res.messages.is_empty() || offset as u64 >= res.total {
                break;
            }
        }
        // Forget ids that can no longer appear in a window.
        if let Some(cutoff) = self.newest.and_then(|n| n.checked_sub(TAIL_OVERLAP * 2)) {
            self.seen.retain(|_, ts| *ts >= cutoff);
        }
    }
}
