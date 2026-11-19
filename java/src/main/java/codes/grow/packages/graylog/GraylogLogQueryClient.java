package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.CancelledException;
import codes.grow.packages.graylog.core.HttpTransport;
import codes.grow.packages.graylog.core.ValidationException;
import codes.grow.packages.graylog.logging.LogQueryClient;
import codes.grow.packages.graylog.logging.LogRecord;
import codes.grow.packages.graylog.logging.LogSearchResult;
import codes.grow.packages.graylog.logging.SearchOptions;
import codes.grow.packages.graylog.logging.SortOrder;
import codes.grow.packages.graylog.logging.TailHandle;
import codes.grow.packages.graylog.logging.TailOptions;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * The {@link LogQueryClient} of the logging category on top of Graylog's Views search API. Queries
 * use Graylog's Lucene syntax ({@code marker:abc}, {@code "exact phrase"}, {@code level:<=3},
 * {@code trace_id:4bf9...}).
 */
public final class GraylogLogQueryClient implements LogQueryClient {
  /** Default poll interval of {@link #tail(String, Consumer)} (Graylog has no streaming API). */
  public static final Duration DEFAULT_TAIL_INTERVAL = Duration.ofSeconds(2);

  /**
   * How far back each tail poll looks before the newest record seen, so records that become
   * searchable late (ingest takes 1–2 s) are not missed; duplicates are removed by message id.
   */
  static final Duration TAIL_OVERLAP = Duration.ofSeconds(10);

  private final GraylogClient client;
  private final GraylogLogQueryClientOptions options;

  GraylogLogQueryClient(GraylogClient client, GraylogLogQueryClientOptions options) {
    this.client = client;
    this.options = options;
  }

  /**
   * Returns the options.
   *
   * @return the options
   */
  public GraylogLogQueryClientOptions options() {
    return options;
  }

  /**
   * Returns normalized records (see {@link GraylogRecords#fromMessage}) matching {@code query}
   * between {@code start} and {@code end} (defaults: end = now, start = end minus the default
   * window), newest first by default, ties broken by {@code gl2_message_id}. The cursor is the
   * offset of the next page; {@code nextCursor} is set while more matches exist and {@code total}
   * is Graylog's match count.
   */
  @Override
  public LogSearchResult search(String query, SearchOptions options) {
    return HttpTransport.await(searchAsync(query, options), "logs.search");
  }

  @Override
  public CompletableFuture<LogSearchResult> searchAsync(String query, SearchOptions options) {
    SearchOptions o = options == null ? SearchOptions.defaults() : options;
    int offset = 0;
    if (o.cursor().isPresent()) {
      try {
        offset = Integer.parseInt(o.cursor().get());
      } catch (NumberFormatException e) {
        offset = -1;
      }
      if (offset < 0) {
        return CompletableFuture.failedFuture(
            new ValidationException("logs.search: invalid cursor"));
      }
    }
    Instant end = o.end().orElseGet(Instant::now);
    Instant start = o.start().orElse(end.minus(this.options.defaultWindow()));
    MessageSearchOptions mo =
        MessageSearchOptions.builder()
            .start(start)
            .end(end)
            .limit(Math.min(o.limit(), MessageSearchOptions.MAX_LIMIT))
            .offset(offset)
            .streams(this.options.streams())
            .sort(
                new SearchSort("timestamp", o.order()), new SearchSort("gl2_message_id", o.order()))
            .build();
    return client
        .searchAsync(query, mo)
        .thenApply(
            r ->
                new LogSearchResult(
                    r.records(),
                    r.nextOffset().isPresent()
                        ? Optional.of(Integer.toString(r.nextOffset().getAsInt()))
                        : Optional.empty(),
                    OptionalLong.of(r.total())));
  }

  /** Returns the titles of every stream (all pages), sorted. */
  @Override
  public List<String> listStreams() {
    return HttpTransport.await(listStreamsAsync(), "logs.listStreams");
  }

  @Override
  public CompletableFuture<List<String>> listStreamsAsync() {
    return client
        .listAllStreamsAsync()
        .thenApply(streams -> streams.stream().map(GraylogStream::title).sorted().toList());
  }

  /** Returns every indexed field name ({@code GET /api/system/fields}), sorted. */
  @Override
  public List<String> listLabels() {
    return client.listFields();
  }

  @Override
  public CompletableFuture<List<String>> listLabelsAsync() {
    return client.listFieldsAsync();
  }

  /**
   * Tails with the default poll interval of 2 s, starting now.
   *
   * @param query Lucene query
   * @param onRecord callback, called once per new record, oldest first
   * @return the handle
   */
  public TailHandle tail(String query, Consumer<LogRecord> onRecord) {
    return tail(query, onRecord, new TailOptions(null, DEFAULT_TAIL_INTERVAL, null));
  }

  /**
   * Polls search every {@code options.interval()} (Graylog has no streaming API) and calls {@code
   * onRecord} once per new matching record, oldest first, starting at {@code options.start()}
   * (default now). Each poll looks back 10 s before the newest record seen and drops duplicates by
   * message id, so late records are delivered too. Search errors go to {@code options.onError()}
   * and polling continues. The tail stops with the handle or when the client is closed.
   */
  @Override
  public TailHandle tail(String query, Consumer<LogRecord> onRecord, TailOptions options) {
    if (onRecord == null) {
      throw new ValidationException("logs.tail: onRecord is required");
    }
    if (client.isClosed()) {
      throw new CancelledException("logs.tail: client is closed");
    }
    TailOptions o = options == null ? new TailOptions(null, DEFAULT_TAIL_INTERVAL, null) : options;
    Duration interval =
        o.interval().isZero() || o.interval().isNegative() ? DEFAULT_TAIL_INTERVAL : o.interval();
    Tailer tailer = new Tailer(query, onRecord, o.start().orElseGet(Instant::now), o.onError());
    Thread thread =
        new Thread(
            () -> {
              while (!tailer.stopped) {
                tailer.poll();
                try {
                  TimeUnit.NANOSECONDS.sleep(interval.toNanos());
                } catch (InterruptedException e) {
                  return;
                }
              }
            },
            "grow-graylog-tail");
    thread.setDaemon(true);
    TailHandle handle =
        () -> {
          tailer.stopped = true;
          thread.interrupt();
          if (Thread.currentThread() != thread) {
            try {
              thread.join(TimeUnit.SECONDS.toMillis(5));
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
            }
          }
        };
    thread.start();
    client.register(handle);
    return handle;
  }

  /** State of one polling tail. */
  final class Tailer {
    final String query;
    final Consumer<LogRecord> onRecord;
    final Instant since;
    final Consumer<Throwable> onError;
    final Map<String, Instant> seen = new HashMap<>();
    Instant newest = Instant.EPOCH;
    volatile boolean stopped;

    Tailer(String query, Consumer<LogRecord> onRecord, Instant since, Consumer<Throwable> onError) {
      this.query = query;
      this.onRecord = onRecord;
      this.since = since;
      this.onError = onError;
    }

    void poll() {
      Instant from = since;
      Instant overlap = newest.minus(TAIL_OVERLAP);
      if (overlap.isAfter(from)) {
        from = overlap;
      }
      int offset = 0;
      while (!stopped) {
        MessageSearchResult res;
        try {
          res =
              client.search(
                  query,
                  MessageSearchOptions.builder()
                      .start(from)
                      .end(Instant.now().plus(Duration.ofMinutes(1)))
                      .limit(1000)
                      .offset(offset)
                      .streams(options.streams())
                      .sort(
                          new SearchSort("timestamp", SortOrder.ASC),
                          new SearchSort("gl2_message_id", SortOrder.ASC))
                      .build());
        } catch (RuntimeException e) {
          if (!stopped) {
            try {
              onError.accept(e);
            } catch (RuntimeException ignored) {
              // a failing callback must not stop the tail
            }
          }
          return;
        }
        for (GraylogMessage m : res.messages()) {
          if (stopped) {
            return;
          }
          if (!m.id().isEmpty() && seen.containsKey(m.id())) {
            continue;
          }
          Instant ts = m.timestamp().orElse(Instant.EPOCH);
          seen.put(m.id(), ts);
          if (ts.isAfter(newest)) {
            newest = ts;
          }
          try {
            onRecord.accept(m.toLogRecord());
          } catch (RuntimeException ignored) {
            // a failing callback must not stop the tail
          }
        }
        offset += res.messages().size();
        if (res.messages().isEmpty() || offset >= res.total()) {
          break;
        }
      }
      Instant cutoff = newest.minus(TAIL_OVERLAP.multipliedBy(2));
      seen.values().removeIf(ts -> ts.isBefore(cutoff));
    }
  }
}
