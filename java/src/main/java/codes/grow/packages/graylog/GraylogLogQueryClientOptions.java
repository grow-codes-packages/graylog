package codes.grow.packages.graylog;

import java.time.Duration;
import java.util.List;

/**
 * Options of {@link GraylogClient#logQueryClient(GraylogLogQueryClientOptions)}.
 *
 * @param streams limits every search to these stream ids (empty = every readable stream)
 * @param defaultWindow search window when {@code SearchOptions.start} is unset: end minus this
 *     (default 1 h)
 */
public record GraylogLogQueryClientOptions(List<String> streams, Duration defaultWindow) {
  /** Default search window. */
  public static final Duration DEFAULT_WINDOW = Duration.ofHours(1);

  /** Copies the list and applies the defaults. */
  public GraylogLogQueryClientOptions {
    streams = streams == null ? List.of() : List.copyOf(streams);
    defaultWindow =
        defaultWindow == null || defaultWindow.isZero() || defaultWindow.isNegative()
            ? DEFAULT_WINDOW
            : defaultWindow;
  }

  /**
   * Returns the defaults (all streams, 1 h window).
   *
   * @return default options
   */
  public static GraylogLogQueryClientOptions defaults() {
    return new GraylogLogQueryClientOptions(null, null);
  }

  /**
   * Returns options limited to some streams.
   *
   * @param streams stream ids
   * @return the options
   */
  public static GraylogLogQueryClientOptions streams(String... streams) {
    return new GraylogLogQueryClientOptions(List.of(streams), null);
  }
}
