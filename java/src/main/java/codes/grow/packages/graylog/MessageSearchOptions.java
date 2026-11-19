package codes.grow.packages.graylog;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Options of {@link GraylogClient#search(String, MessageSearchOptions)}. Give at most one of {@code
 * range}, {@code start}/{@code end} and {@code keyword}; the defaults search the last 5 minutes of
 * every readable stream, newest first, 100 per page.
 */
public final class MessageSearchOptions {
  /** Default relative range when no range is given. */
  public static final Duration DEFAULT_RANGE = Duration.ofSeconds(300);

  /** Default page size. */
  public static final int DEFAULT_LIMIT = 100;

  /** Largest page size (OpenSearch's default {@code max_result_window}). */
  public static final int MAX_LIMIT = 10_000;

  private final Duration range;
  private final Instant start;
  private final Instant end;
  private final String keyword;
  private final int limit;
  private final int offset;
  private final List<String> fields;
  private final List<SearchSort> sort;
  private final List<String> streams;

  private MessageSearchOptions(Builder b) {
    this.range = b.range;
    this.start = b.start;
    this.end = b.end;
    this.keyword = b.keyword;
    this.limit = b.limit;
    this.offset = b.offset;
    this.fields = List.copyOf(b.fields);
    this.sort = List.copyOf(b.sort);
    this.streams = List.copyOf(b.streams);
  }

  /**
   * Returns the defaults.
   *
   * @return default options
   */
  public static MessageSearchOptions defaults() {
    return builder().build();
  }

  /**
   * Starts a builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Returns a builder pre-filled with these options.
   *
   * @return a new builder
   */
  public Builder toBuilder() {
    Builder b = new Builder();
    b.range = range;
    b.start = start;
    b.end = end;
    b.keyword = keyword;
    b.limit = limit;
    b.offset = offset;
    b.fields.addAll(fields);
    b.sort.addAll(sort);
    b.streams.addAll(streams);
    return b;
  }

  /**
   * Returns the relative range ending now (sent in whole seconds, rounded up).
   *
   * @return the range, or empty
   */
  public Optional<Duration> range() {
    return Optional.ofNullable(range);
  }

  /**
   * Returns the start of an absolute range.
   *
   * @return the start, or empty
   */
  public Optional<Instant> start() {
    return Optional.ofNullable(start);
  }

  /**
   * Returns the end of an absolute range.
   *
   * @return the end, or empty
   */
  public Optional<Instant> end() {
    return Optional.ofNullable(end);
  }

  /**
   * Returns the Graylog keyword range (e.g. {@code "last five minutes"}).
   *
   * @return the keyword, or empty
   */
  public Optional<String> keyword() {
    return Optional.ofNullable(keyword);
  }

  /**
   * Returns the page size.
   *
   * @return the limit
   */
  public int limit() {
    return limit;
  }

  /**
   * Returns how many matches to skip.
   *
   * @return the offset
   */
  public int offset() {
    return offset;
  }

  /**
   * Returns the returned fields (empty = all; Graylog always adds {@code _id}).
   *
   * @return the fields
   */
  public List<String> fields() {
    return fields;
  }

  /**
   * Returns the sort keys (empty = timestamp descending).
   *
   * @return the sort keys
   */
  public List<SearchSort> sort() {
    return sort;
  }

  /**
   * Returns the stream ids to search (empty = every readable stream).
   *
   * @return the stream ids
   */
  public List<String> streams() {
    return streams;
  }

  /** Builder of {@link MessageSearchOptions}. */
  public static final class Builder {
    private Duration range;
    private Instant start;
    private Instant end;
    private String keyword;
    private int limit = DEFAULT_LIMIT;
    private int offset;
    private final List<String> fields = new ArrayList<>();
    private final List<SearchSort> sort = new ArrayList<>();
    private final List<String> streams = new ArrayList<>();

    private Builder() {}

    /**
     * Sets a relative range ending now (default 300 s when no other range is given).
     *
     * @param range positive duration
     * @return this builder
     */
    public Builder range(Duration range) {
      this.range = range;
      return this;
    }

    /**
     * Sets the start of an absolute range (default end minus 300 s).
     *
     * @param start instant
     * @return this builder
     */
    public Builder start(Instant start) {
      this.start = start;
      return this;
    }

    /**
     * Sets the end of an absolute range (default now).
     *
     * @param end instant
     * @return this builder
     */
    public Builder end(Instant end) {
      this.end = end;
      return this;
    }

    /**
     * Sets a Graylog keyword range such as {@code "last five minutes"}.
     *
     * @param keyword keyword
     * @return this builder
     */
    public Builder keyword(String keyword) {
      this.keyword = keyword;
      return this;
    }

    /**
     * Sets the page size (default 100, at most 10 000).
     *
     * @param limit 1..10000
     * @return this builder
     */
    public Builder limit(int limit) {
      this.limit = limit;
      return this;
    }

    /**
     * Sets how many matches to skip (pagination).
     *
     * @param offset non-negative offset
     * @return this builder
     */
    public Builder offset(int offset) {
      this.offset = offset;
      return this;
    }

    /**
     * Limits the returned fields.
     *
     * @param fields field names
     * @return this builder
     */
    public Builder fields(String... fields) {
      this.fields.clear();
      this.fields.addAll(Arrays.asList(fields));
      return this;
    }

    /**
     * Sets the sort keys; later keys break ties.
     *
     * @param sort sort keys
     * @return this builder
     */
    public Builder sort(SearchSort... sort) {
      this.sort.clear();
      this.sort.addAll(Arrays.asList(sort));
      return this;
    }

    /**
     * Restricts the search to these stream ids.
     *
     * @param streams stream ids
     * @return this builder
     */
    public Builder streams(String... streams) {
      this.streams.clear();
      this.streams.addAll(Arrays.asList(streams));
      return this;
    }

    /**
     * Restricts the search to these stream ids.
     *
     * @param streams stream ids
     * @return this builder
     */
    public Builder streams(List<String> streams) {
      this.streams.clear();
      this.streams.addAll(streams);
      return this;
    }

    /**
     * Builds the options (validated by the search call).
     *
     * @return the options
     */
    public MessageSearchOptions build() {
      return new MessageSearchOptions(this);
    }
  }
}
