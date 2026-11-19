package codes.grow.packages.graylog;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Tunes the transport built by {@link GraylogClient#gelfTransport(GelfProtocol,
 * GelfTransportOptions)}.
 */
public final class GelfTransportOptions {
  private final GelfCompression compression;
  private final int chunkSize;
  private final boolean bulk;
  private final Map<String, String> headers;

  private GelfTransportOptions(Builder b) {
    this.compression = b.compression;
    this.chunkSize = b.chunkSize;
    this.bulk = b.bulk;
    this.headers = Map.copyOf(b.headers);
  }

  /**
   * Returns the defaults (gzip, chunk size 1420, bulk, no extra headers).
   *
   * @return default options
   */
  public static GelfTransportOptions defaults() {
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
   * Returns whether HTTP batches are sent as one body.
   *
   * @return true for bulk
   */
  public boolean bulk() {
    return bulk;
  }

  /**
   * Returns the extra HTTP headers.
   *
   * @return immutable map
   */
  public Map<String, String> headers() {
    return headers;
  }

  /** Builder of {@link GelfTransportOptions}. */
  public static final class Builder {
    private GelfCompression compression = GelfCompression.GZIP;
    private int chunkSize = GelfUdpTransport.DEFAULT_CHUNK_SIZE;
    private boolean bulk = true;
    private final Map<String, String> headers = new LinkedHashMap<>();

    private Builder() {}

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
     * Adds an HTTP header (for example the input's authorization header).
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
     * Builds the options.
     *
     * @return the options
     */
    public GelfTransportOptions build() {
      return new GelfTransportOptions(this);
    }
  }
}
