package codes.grow.packages.graylog;

import codes.grow.packages.graylog.logging.ExportOptions;
import codes.grow.packages.graylog.logging.ExportResult;
import codes.grow.packages.graylog.logging.LogExporter;
import codes.grow.packages.graylog.logging.LogRecord;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * The {@link LogExporter} of the logging category over GELF: converts records with {@link
 * GelfMessage#fromLogRecord(LogRecord, String)} and sends them through a {@link GelfTransport}.
 */
public final class GelfLogExporter implements LogExporter {
  private final GelfTransport transport;
  private final String host;

  /**
   * Creates an exporter.
   *
   * @param transport the transport (closed by {@link #shutdown()})
   * @param host GELF host of records without {@code resource["host.name"]} ({@code null} = the
   *     local host name)
   */
  public GelfLogExporter(GelfTransport transport, String host) {
    this.transport = Objects.requireNonNull(transport, "transport");
    this.host = host;
  }

  /**
   * Returns the underlying transport.
   *
   * @return the transport
   */
  public GelfTransport transport() {
    return transport;
  }

  /**
   * Converts and sends records; {@link ExportOptions#gzip()} is passed to the transport (only HTTP
   * uses it). Client-side rejections are counted; network errors fail the future.
   */
  @Override
  public CompletableFuture<ExportResult> export(List<LogRecord> records, ExportOptions options) {
    List<GelfMessage> messages = new ArrayList<>(records.size());
    for (LogRecord r : records) {
      messages.add(GelfMessage.fromLogRecord(r, host));
    }
    return transport
        .sendAsync(messages, GelfSendOptions.gzip(options.gzip()))
        .thenApply(res -> new ExportResult(res.sent(), res.rejected(), res.error()));
  }

  /** Closes the transport. */
  @Override
  public CompletableFuture<Void> shutdown() {
    transport.close();
    return CompletableFuture.completedFuture(null);
  }
}
