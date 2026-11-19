package codes.grow.packages.graylog;

import codes.grow.packages.graylog.logging.LogRecord;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

/**
 * One page of {@link GraylogClient#search(String, MessageSearchOptions)}.
 *
 * @param messages the messages
 * @param total number of matches of the whole query
 * @param from start of the effective time range
 * @param to end of the effective time range
 * @param nextOffset offset of the next page (empty when there is none)
 */
public record MessageSearchResult(
    List<GraylogMessage> messages,
    long total,
    Optional<Instant> from,
    Optional<Instant> to,
    OptionalInt nextOffset) {
  /** Copies the list and normalises {@code null} values. */
  public MessageSearchResult {
    messages = messages == null ? List.of() : List.copyOf(messages);
    from = from == null ? Optional.empty() : from;
    to = to == null ? Optional.empty() : to;
    nextOffset = nextOffset == null ? OptionalInt.empty() : nextOffset;
  }

  /**
   * Normalises every message into a log record.
   *
   * @return the records
   */
  public List<LogRecord> records() {
    return messages.stream().map(GraylogMessage::toLogRecord).toList();
  }
}
