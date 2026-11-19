package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.Secret;
import codes.grow.packages.graylog.logging.BatchOptions;
import codes.grow.packages.graylog.logging.RedactionProcessor;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Options of {@link GraylogClient#logClient(GraylogLogClientOptions)}: the batching options plus
 * the transport choice.
 */
public final class GraylogLogClientOptions {
  private final BatchOptions batchOptions;
  private final Map<String, Object> resource;
  private final RedactionProcessor redaction;
  private final GelfProtocol protocol;
  private final String host;
  private final GelfTransport transport;
  private final GelfCompression compression;
  private final int chunkSize;
  private final boolean bulk;
  private final Map<String, String> headers;
  private final Secret bearerToken;

  private GraylogLogClientOptions(Builder b) {
    this.batchOptions = b.batchOptions;
    this.resource = Map.copyOf(b.resource);
    this.redaction = b.redaction;
    this.protocol = b.protocol;
    this.host = b.host;
    this.transport = b.transport;
    this.compression = b.compression;
    this.chunkSize = b.chunkSize;
    this.bulk = b.bulk;
    this.headers = Map.copyOf(b.headers);
    this.bearerToken = b.bearerToken;
  }

  /**
   * Returns the defaults (configured protocol, default batching and redaction).
   *
   * @return default options
   */
  public static GraylogLogClientOptions defaults() {
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
   * Returns the batching options.
   *
   * @return the options
   */
  public BatchOptions batchOptions() {
    return batchOptions;
  }

  /**
   * Returns the resource attributes merged into every record.
   *
   * @return immutable map
   */
  public Map<String, Object> resource() {
    return resource;
  }

  /**
   * Returns the redaction processor ({@code null} disables redaction).
   *
   * @return the processor
   */
  public RedactionProcessor redaction() {
    return redaction;
  }

  /**
   * Returns the protocol (empty = {@link GraylogConfig#gelfProtocol()}).
   *
   * @return the protocol
   */
  public Optional<GelfProtocol> protocol() {
    return Optional.ofNullable(protocol);
  }

  /**
   * Returns the GELF host of records without {@code resource["host.name"]}.
   *
   * @return the host, or empty for the local host name
   */
  public Optional<String> host() {
    return Optional.ofNullable(host);
  }

  /**
   * Returns the transport used instead of building one.
   *
   * @return the transport, or empty
   */
  public Optional<GelfTransport> transport() {
    return Optional.ofNullable(transport);
  }

  /**
   * Returns the UDP compression.
   *
   * @return the compression
   */
  public GelfCompression compression() {
    return compression;
  }

  /**
   * Returns the UDP chunk size.
   *
   * @return the chunk size
   */
  public int chunkSize() {
    return chunkSize;
  }

  /**
   * Returns whether HTTP batches are one body.
   *
   * @return true for bulk
   */
  public boolean bulk() {
    return bulk;
  }

  /**
   * Returns the extra HTTP headers or OTLP gRPC metadata.
   *
   * @return immutable map
   */
  public Map<String, String> headers() {
    return headers;
  }

  /**
   * Returns the OTLP input's bearer token.
   *
   * @return the token, or empty
   */
  public Optional<Secret> bearerToken() {
    return Optional.ofNullable(bearerToken);
  }

  GelfTransportOptions transportOptions() {
    GelfTransportOptions.Builder b =
        GelfTransportOptions.builder().compression(compression).chunkSize(chunkSize).bulk(bulk);
    headers.forEach(b::header);
    return b.build();
  }

  /** Builder of {@link GraylogLogClientOptions}. */
  public static final class Builder {
    private BatchOptions batchOptions = BatchOptions.defaults();
    private final Map<String, Object> resource = new LinkedHashMap<>();
    private RedactionProcessor redaction = RedactionProcessor.defaults();
    private GelfProtocol protocol;
    private String host;
    private GelfTransport transport;
    private GelfCompression compression = GelfCompression.GZIP;
    private int chunkSize = GelfUdpTransport.DEFAULT_CHUNK_SIZE;
    private boolean bulk = true;
    private final Map<String, String> headers = new LinkedHashMap<>();
    private Secret bearerToken;

    private Builder() {}

    /**
     * Sets the batching options.
     *
     * @param options options
     * @return this builder
     */
    public Builder batchOptions(BatchOptions options) {
      this.batchOptions = options == null ? BatchOptions.defaults() : options;
      return this;
    }

    /**
     * Sets the resource attributes (e.g. {@code service.name}).
     *
     * @param resource attributes
     * @return this builder
     */
    public Builder resource(Map<String, ?> resource) {
      this.resource.clear();
      if (resource != null) {
        this.resource.putAll(resource);
      }
      return this;
    }

    /**
     * Sets the redaction processor ({@code null} disables redaction).
     *
     * @param redaction processor
     * @return this builder
     */
    public Builder redaction(RedactionProcessor redaction) {
      this.redaction = redaction;
      return this;
    }

    /**
     * Sets the protocol: UDP, TCP, HTTP or OTLP (default: the configured GELF protocol).
     *
     * @param protocol protocol
     * @return this builder
     */
    public Builder protocol(GelfProtocol protocol) {
      this.protocol = protocol;
      return this;
    }

    /**
     * Sets the GELF host of records without {@code resource["host.name"]}.
     *
     * @param host host
     * @return this builder
     */
    public Builder host(String host) {
      this.host = host;
      return this;
    }

    /**
     * Uses this transport instead of building one (closed with the log client).
     *
     * @param transport transport
     * @return this builder
     */
    public Builder transport(GelfTransport transport) {
      this.transport = transport;
      return this;
    }

    /**
     * Sets the UDP compression (default gzip).
     *
     * @param compression compression
     * @return this builder
     */
    public Builder compression(GelfCompression compression) {
      this.compression = compression == null ? GelfCompression.GZIP : compression;
      return this;
    }

    /**
     * Sets the UDP chunk size (default 1420).
     *
     * @param chunkSize 64..65507
     * @return this builder
     */
    public Builder chunkSize(int chunkSize) {
      this.chunkSize = chunkSize;
      return this;
    }

    /**
     * Turns HTTP bulk bodies on or off (default on).
     *
     * @param bulk true for bulk
     * @return this builder
     */
    public Builder bulk(boolean bulk) {
      this.bulk = bulk;
      return this;
    }

    /**
     * Adds an HTTP header or OTLP gRPC metadata entry.
     *
     * @param name name
     * @param value value
     * @return this builder
     */
    public Builder header(String name, String value) {
      this.headers.put(name, value);
      return this;
    }

    /**
     * Sets the OTLP input's bearer token.
     *
     * @param token token
     * @return this builder
     */
    public Builder bearerToken(Secret token) {
      this.bearerToken = token;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public GraylogLogClientOptions build() {
      return new GraylogLogClientOptions(this);
    }
  }
}
