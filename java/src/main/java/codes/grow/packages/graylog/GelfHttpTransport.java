package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.ConfigException;
import codes.grow.packages.graylog.core.HttpTransport;
import codes.grow.packages.graylog.core.TransportRequest;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * GELF over HTTP: posts messages to a GELF HTTP input ({@code 202 Accepted}).
 *
 * <p>By default a batch is one gzip body of newline-terminated messages (input option {@code
 * enable_bulk_receiving}); every message ends with {@code \n}, also single ones (Graylog 7.0 drops
 * the first message of the third and later request on a reused connection otherwise). Graylog
 * answers 202 even for invalid JSON or a missing {@code short_message} and drops the message, so
 * messages are validated when they are built. Timeouts, retries, TLS, proxy, hooks and logger come
 * from a {@link GraylogConfig}.
 */
public final class GelfHttpTransport implements GelfTransport {
  private final HttpTransport transport;
  private final String path;
  private final boolean gzip;
  private final boolean bulk;
  private final String url;

  private GelfHttpTransport(Builder b) {
    URI u;
    try {
      u = new URI(b.url == null ? "" : b.url);
    } catch (URISyntaxException e) {
      throw new ConfigException("gelf.http: url must be an http(s) URL");
    }
    if (!GraylogConfig.isHttpUrl(b.url)) {
      throw new ConfigException("gelf.http: url must be an http(s) URL");
    }
    String base = u.getScheme() + "://" + u.getRawAuthority();
    String p = u.getRawPath();
    this.path = p == null || p.isEmpty() ? "/gelf" : p;
    this.url = b.url;
    this.gzip = b.gzip;
    this.bulk = b.bulk;
    GraylogConfig cfg = b.config != null ? b.config : GraylogConfig.builder().build();
    this.transport = new HttpTransport(cfg.toTransportConfig(base, b.headers));
  }

  /**
   * Starts a builder.
   *
   * @param url URL of the GELF HTTP input, e.g. {@code http://graylog:12202/gelf}
   * @return a new builder (gzip and bulk on)
   */
  public static Builder builder(String url) {
    return new Builder(url);
  }

  @Override
  public GelfProtocol protocol() {
    return GelfProtocol.HTTP;
  }

  /**
   * Returns the input URL.
   *
   * @return the URL
   */
  public String url() {
    return url;
  }

  /**
   * Builds the request bodies: one body per call (bulk) or one per message.
   *
   * @param messages messages
   * @param bulk true for one newline-delimited body
   * @return the uncompressed bodies
   */
  static List<byte[]> bodies(List<GelfMessage> messages, boolean bulk) {
    List<byte[]> out = new ArrayList<>();
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    for (GelfMessage m : messages) {
      buf.writeBytes(m.encode());
      buf.write('\n');
      if (!bulk) {
        out.add(buf.toByteArray());
        buf.reset();
      }
    }
    if (bulk && !messages.isEmpty()) {
      out.add(buf.toByteArray());
    }
    return out;
  }

  @Override
  public GelfSendResult send(List<GelfMessage> messages, GelfSendOptions options) {
    return HttpTransport.await(sendAsync(messages, options), "gelf.http");
  }

  /** Posts the bodies one after another; the future fails with the first request error. */
  @Override
  public CompletableFuture<GelfSendResult> sendAsync(
      List<GelfMessage> messages, GelfSendOptions options) {
    try {
      GelfIo.requireMessages("gelf.http", messages);
    } catch (RuntimeException e) {
      return CompletableFuture.failedFuture(e);
    }
    if (transport.isClosed()) {
      return CompletableFuture.failedFuture(GelfIo.closed("gelf.http"));
    }
    boolean gz = options == null ? gzip : options.gzip().orElse(gzip);
    List<byte[]> bodies = bodies(messages, bulk);
    int perBody = bulk ? messages.size() : 1;
    CompletableFuture<Integer> chain = CompletableFuture.completedFuture(0);
    for (byte[] raw : bodies) {
      chain =
          chain.thenCompose(
              sent -> {
                TransportRequest.Builder r =
                    TransportRequest.post(path)
                        .operation("gelf.http")
                        .header("X-Requested-By", GraylogConfig.DEFAULT_REQUESTED_BY);
                if (gz) {
                  r.body(GelfIo.compress(GelfCompression.GZIP, raw), "application/json")
                      .header("Content-Encoding", "gzip");
                } else {
                  r.body(raw, "application/json");
                }
                return transport.sendAsync(r.build()).thenApply(resp -> sent + perBody);
              });
    }
    return chain.thenApply(GelfSendResult::ofSent);
  }

  /** Releases connections. Idempotent. */
  @Override
  public void close() {
    transport.close();
  }

  @Override
  public String toString() {
    return "GelfHttpTransport{" + url + ", gzip=" + gzip + ", bulk=" + bulk + "}";
  }

  /** Builder of a {@link GelfHttpTransport}. */
  public static final class Builder {
    private final String url;
    private boolean gzip = true;
    private boolean bulk = true;
    private final Map<String, String> headers = new LinkedHashMap<>();
    private GraylogConfig config;

    private Builder(String url) {
      this.url = url;
    }

    /**
     * Turns gzip bodies on or off (default on).
     *
     * @param gzip true for gzip
     * @return this builder
     */
    public Builder gzip(boolean gzip) {
      this.gzip = gzip;
      return this;
    }

    /**
     * Turns bulk bodies on or off (default on). Without bulk every message is its own request (for
     * inputs without {@code enable_bulk_receiving}).
     *
     * @param bulk true for one body per call
     * @return this builder
     */
    public Builder bulk(boolean bulk) {
      this.bulk = bulk;
      return this;
    }

    /**
     * Adds a request header (for example the input's optional authorization header); sensitive
     * values are redacted.
     *
     * @param name header name
     * @param value header value
     * @return this builder
     */
    public Builder header(String name, String value) {
      this.headers.put(name, value);
      return this;
    }

    /**
     * Adds request headers.
     *
     * @param headers headers ({@code null} is ignored)
     * @return this builder
     */
    public Builder headers(Map<String, String> headers) {
      if (headers != null) {
        this.headers.putAll(headers);
      }
      return this;
    }

    /**
     * Uses the timeouts, retries, TLS, proxy, hooks and logger of {@code config} (its URL, headers
     * and credentials are ignored).
     *
     * @param config configuration
     * @return this builder
     */
    public Builder config(GraylogConfig config) {
      this.config = config;
      return this;
    }

    /**
     * Validates and builds the transport.
     *
     * @return the transport
     * @throws ConfigException for a URL that is not http(s)
     */
    public GelfHttpTransport build() {
      return new GelfHttpTransport(this);
    }
  }
}
