package graylog

import (
	"context"
	"log/slog"
	"sort"
	"strconv"
	"sync"
	"time"
)

// DefaultTailInterval is the poll interval of LogQuery.Tail.
const DefaultTailInterval = 2 * time.Second

// tailOverlap is how far back each tail poll looks before the newest record
// seen, so records that become searchable late (ingest takes 1–2 s) are not
// missed; duplicates are removed by message id.
const tailOverlap = 10 * time.Second

// LogQuery is the LogQueryClient of the logging category on top of Graylog's
// Views search API. Queries use Graylog's Lucene syntax ("marker:abc",
// "\"exact phrase\"", "level:<=3", "trace_id:4bf9…").
type LogQuery struct {
	client  *Client
	streams []string
	window  time.Duration
}

var _ LogQueryClient = (*LogQuery)(nil)

// DefaultLogQueryWindow is the search window of LogQuery.Search when no start
// is given.
const DefaultLogQueryWindow = time.Hour

// LogQueryOptions configure Client.LogQuery. The zero value is valid.
type LogQueryOptions struct {
	// Streams limits every search to these stream ids (default: every
	// readable stream).
	Streams []string
	// DefaultWindow is the search window when SearchOptions.Start is unset:
	// End minus this (default 1 h).
	DefaultWindow time.Duration
}

// LogQuery returns the LogQueryClient of this client.
func (c *Client) LogQuery(opts LogQueryOptions) *LogQuery {
	w := opts.DefaultWindow
	if w <= 0 {
		w = DefaultLogQueryWindow
	}
	return &LogQuery{client: c, streams: append([]string(nil), opts.Streams...), window: w}
}

// Search returns normalized records (see LogRecordFromMessage) matching
// query between opts.Start and opts.End (defaults: End = now, Start = End −
// DefaultWindow), newest first by default, ties broken by gl2_message_id. The cursor is the offset of the next page; NextCursor is set while
// more matches exist and Total is Graylog's match count.
func (q *LogQuery) Search(ctx context.Context, query string, opts SearchOptions) (LogSearchResult, error) {
	opts = opts.WithDefaults()
	offset := 0
	if opts.Cursor != "" {
		n, err := strconv.Atoi(opts.Cursor)
		if err != nil || n < 0 {
			return LogSearchResult{}, ValidationError("logs.search", "invalid cursor")
		}
		offset = n
	}
	if opts.Order != OrderAsc && opts.Order != OrderDesc {
		return LogSearchResult{}, ValidationError("logs.search", `order must be "asc" or "desc"`)
	}
	end := opts.End
	if end.IsZero() {
		end = time.Now()
	}
	start := opts.Start
	if start.IsZero() {
		start = end.Add(-q.window)
	}
	res, err := q.client.Search(ctx, query, MessageSearchOptions{
		Start: start, End: end, Limit: min(opts.Limit, MaxSearchLimit), Offset: offset, Streams: q.streams,
		Sort: []SearchSort{{Field: DefaultMessageSortField, Order: opts.Order}, {Field: "gl2_message_id", Order: opts.Order}},
	})
	if err != nil {
		return LogSearchResult{}, err
	}
	total := res.Total
	out := LogSearchResult{Records: res.Records(), Total: &total}
	if res.NextOffset > 0 {
		out.NextCursor = strconv.Itoa(res.NextOffset)
	}
	return out, nil
}

// ListStreams returns the titles of every stream (all pages, sorted).
func (q *LogQuery) ListStreams(ctx context.Context) ([]string, error) {
	streams, err := q.client.listAllStreams(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(streams))
	for i, s := range streams {
		out[i] = s.Title
	}
	sort.Strings(out)
	return out, nil
}

// ListLabels returns every indexed field name (GET /api/system/fields), sorted.
func (q *LogQuery) ListLabels(ctx context.Context) ([]string, error) {
	return q.client.ListFields(ctx)
}

// WaitForLog polls Search until a record matches (see the package-level WaitForLog).
func (q *LogQuery) WaitForLog(ctx context.Context, query string, opts WaitForLogOptions) (LogRecord, error) {
	return WaitForLog(ctx, q, query, opts)
}

// tailHandle stops a polling tail.
type tailHandle struct {
	once   sync.Once
	cancel context.CancelFunc
	done   chan struct{}
}

// Stop ends the tail and waits for the poll goroutine. It is idempotent.
func (h *tailHandle) Stop() {
	h.once.Do(h.cancel)
	<-h.done
}

// Tail polls Search every opts.Interval (default 2 s; Graylog has no
// streaming API) and calls onRecord once per new matching record, oldest
// first, starting at opts.Start (default now). Each poll looks back 10 s
// before the newest record seen and drops duplicates by message id, so late
// records are delivered too. Search errors are logged and polling continues.
// The tail stops with the handle, when ctx is done or when the client is closed.
func (q *LogQuery) Tail(ctx context.Context, query string, onRecord func(LogRecord), opts TailOptions) (TailHandle, error) {
	if onRecord == nil {
		return nil, ValidationError("logs.tail", "onRecord is required")
	}
	if q.client.isClosed() {
		return nil, &Error{Code: ErrorCodeCancelled, Message: "logs.tail: client is closed"}
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = DefaultTailInterval
	}
	start := opts.Start
	if start.IsZero() {
		start = time.Now()
	}
	tctx, cancel := context.WithCancel(ctx)
	h := &tailHandle{cancel: cancel, done: make(chan struct{})}
	q.client.onClose(func() { h.once.Do(cancel) })
	go func() {
		defer close(h.done)
		t := &tailer{q: q, query: query, onRecord: onRecord, since: start, seen: map[string]time.Time{}}
		for {
			t.poll(tctx)
			if sleepContext(tctx, interval) != nil {
				return
			}
		}
	}()
	return h, nil
}

type tailer struct {
	q        *LogQuery
	query    string
	onRecord func(LogRecord)
	since    time.Time // start of the tail (lower bound of every window)
	newest   time.Time // newest record timestamp delivered
	seen     map[string]time.Time
}

func (t *tailer) poll(ctx context.Context) {
	from := t.since
	if !t.newest.IsZero() && t.newest.Add(-tailOverlap).After(from) {
		from = t.newest.Add(-tailOverlap)
	}
	for offset := 0; ; {
		res, err := t.q.client.Search(ctx, t.query, MessageSearchOptions{
			Start: from, End: time.Now().Add(time.Minute), Limit: 1000, Offset: offset, Streams: t.q.streams,
			Sort: []SearchSort{{Field: DefaultMessageSortField, Order: OrderAsc}, {Field: "gl2_message_id", Order: OrderAsc}},
		})
		if err != nil {
			if ctx.Err() == nil {
				t.q.client.transport.log(slog.LevelWarn, "logs.tail: search failed", slog.String("error", err.Error()))
			}
			return
		}
		for _, m := range res.Messages {
			if ctx.Err() != nil {
				return
			}
			if _, dup := t.seen[m.ID]; dup && m.ID != "" {
				continue
			}
			t.seen[m.ID] = m.Timestamp
			if m.Timestamp.After(t.newest) {
				t.newest = m.Timestamp
			}
			safeCall(func() { t.onRecord(m.Record()) })
		}
		offset += len(res.Messages)
		if len(res.Messages) == 0 || offset >= res.Total {
			break
		}
	}
	// Forget ids that can no longer appear in a window.
	cutoff := t.newest.Add(-2 * tailOverlap)
	for id, ts := range t.seen {
		if ts.Before(cutoff) {
			delete(t.seen, id)
		}
	}
}
