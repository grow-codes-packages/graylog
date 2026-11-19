package codes.grow.packages.graylog;

import java.util.Optional;

/**
 * Per-call options of {@link GelfTransport#send(java.util.List, GelfSendOptions)}.
 *
 * @param gzip overrides the HTTP transport's compression for this call (empty = the transport
 *     default); UDP and TCP ignore it
 */
public record GelfSendOptions(Optional<Boolean> gzip) {
  /** Normalises {@code null} to empty. */
  public GelfSendOptions {
    gzip = gzip == null ? Optional.empty() : gzip;
  }

  /**
   * Returns the defaults (transport compression).
   *
   * @return options without overrides
   */
  public static GelfSendOptions defaults() {
    return new GelfSendOptions(Optional.empty());
  }

  /**
   * Returns options that force gzip on or off.
   *
   * @param gzip true for gzip bodies
   * @return the options
   */
  public static GelfSendOptions gzip(boolean gzip) {
    return new GelfSendOptions(Optional.of(gzip));
  }
}
