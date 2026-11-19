package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.ConfigException;
import codes.grow.packages.graylog.core.GraylogException;
import codes.grow.packages.graylog.core.ValidationException;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Fire-and-forget GELF over UDP: one datagram per message, compressed (gzip by default) and split
 * into at most 128 chunks. Delivery is best-effort (UDP has no acknowledgement).
 */
public final class GelfUdpTransport implements GelfTransport {
  /** Chunk header size: magic {@code 0x1e 0x0f} (2), message id (8), sequence (1), count (1). */
  public static final int CHUNK_HEADER_SIZE = 12;

  /** GELF limit of chunks per message. */
  public static final int MAX_CHUNKS = 128;

  /** Default datagram size including the chunk header (fits a 1500-byte Ethernet MTU). */
  public static final int DEFAULT_CHUNK_SIZE = 1420;

  private static final SecureRandom RANDOM = new SecureRandom();

  private final String host;
  private final int port;
  private final GelfCompression compression;
  private final int chunkSize;
  private DatagramSocket socket;
  private boolean closed;

  private GelfUdpTransport(Builder b) {
    this.host = GelfIo.checkHostPort("gelf.udp", b.host, b.port);
    this.port = b.port;
    this.compression = b.compression;
    if (b.chunkSize < 64 || b.chunkSize > 65507) {
      throw new ConfigException("gelf.udp: chunkSize must be an integer 64..65507");
    }
    this.chunkSize = b.chunkSize;
  }

  /**
   * Starts a builder.
   *
   * @param host host of the GELF UDP input
   * @return a new builder (port 12201, gzip, chunk size 1420)
   */
  public static Builder builder(String host) {
    return new Builder(host);
  }

  @Override
  public GelfProtocol protocol() {
    return GelfProtocol.UDP;
  }

  /**
   * Returns the compression.
   *
   * @return the compression
   */
  public GelfCompression compression() {
    return compression;
  }

  /**
   * Returns the datagram size including the chunk header.
   *
   * @return the chunk size
   */
  public int chunkSize() {
    return chunkSize;
  }

  /**
   * Compresses {@code payload} and splits it into datagrams: one datagram when it fits {@code
   * chunkSize}, else chunks {@code 0x1e 0x0f | id(8) | seq | count | data}.
   *
   * @param payload JSON bytes
   * @param compression compression ({@code null} = gzip)
   * @param chunkSize datagram size including the header (0 = 1420)
   * @param messageId 8-byte message id ({@code null} = random)
   * @return the datagrams
   * @throws ValidationException when more than 128 chunks are needed or the chunk size does not
   *     exceed the header
   */
  public static List<byte[]> encode(
      byte[] payload, GelfCompression compression, int chunkSize, byte[] messageId) {
    GelfCompression c = compression == null ? GelfCompression.GZIP : compression;
    int size = chunkSize == 0 ? DEFAULT_CHUNK_SIZE : chunkSize;
    if (size <= CHUNK_HEADER_SIZE) {
      throw new ValidationException("gelf.udp: chunk size must exceed the 12-byte header");
    }
    byte[] data = GelfIo.compress(c, payload);
    List<byte[]> out = new ArrayList<>();
    if (data.length <= size) {
      out.add(data);
      return out;
    }
    int per = size - CHUNK_HEADER_SIZE;
    int count = (data.length + per - 1) / per;
    if (count > MAX_CHUNKS) {
      throw new ValidationException(
          "gelf.udp: message needs "
              + count
              + " chunks (max 128); use TCP or HTTP for large messages");
    }
    byte[] id = new byte[8];
    if (messageId != null) {
      System.arraycopy(messageId, 0, id, 0, Math.min(8, messageId.length));
    } else {
      RANDOM.nextBytes(id);
    }
    for (int seq = 0; seq < count; seq++) {
      int from = seq * per;
      int len = Math.min(per, data.length - from);
      byte[] chunk = new byte[CHUNK_HEADER_SIZE + len];
      chunk[0] = 0x1e;
      chunk[1] = 0x0f;
      System.arraycopy(id, 0, chunk, 2, 8);
      chunk[10] = (byte) seq;
      chunk[11] = (byte) count;
      System.arraycopy(data, from, chunk, CHUNK_HEADER_SIZE, len);
      out.add(chunk);
    }
    return out;
  }

  /**
   * Writes every message as one or more datagrams. Messages that need more than 128 chunks are
   * rejected (counted, not sent).
   */
  @Override
  public synchronized GelfSendResult send(List<GelfMessage> messages, GelfSendOptions options) {
    GelfIo.requireMessages("gelf.udp", messages);
    if (closed) {
      throw GelfIo.closed("gelf.udp");
    }
    int sent = 0;
    int rejected = 0;
    GraylogException error = null;
    for (GelfMessage m : messages) {
      List<byte[]> datagrams;
      try {
        datagrams = encode(m.encode(), compression, chunkSize, null);
      } catch (ValidationException e) {
        rejected++;
        error = e;
        continue;
      }
      try {
        if (socket == null) {
          DatagramSocket s = new DatagramSocket();
          try {
            s.connect(new InetSocketAddress(host, port));
          } catch (IOException | RuntimeException e) {
            s.close();
            throw e;
          }
          socket = s;
        }
        for (byte[] d : datagrams) {
          socket.send(new DatagramPacket(d, d.length));
        }
      } catch (IOException e) {
        dropSocket();
        throw GelfIo.networkError("gelf.udp", e);
      } catch (IllegalArgumentException | SecurityException e) {
        dropSocket();
        throw GelfIo.networkError("gelf.udp", new IOException(e.getMessage(), e));
      }
      sent++;
    }
    return new GelfSendResult(sent, rejected, Optional.ofNullable(error));
  }

  private void dropSocket() {
    if (socket != null) {
      socket.close();
      socket = null;
    }
  }

  /** Closes the socket. Idempotent. */
  @Override
  public synchronized void close() {
    closed = true;
    dropSocket();
  }

  @Override
  public String toString() {
    return "GelfUdpTransport{" + host + ":" + port + ", " + compression + "}";
  }

  /** Builder of a {@link GelfUdpTransport}. */
  public static final class Builder {
    private final String host;
    private int port = GraylogConfig.DEFAULT_GELF_PORT;
    private GelfCompression compression = GelfCompression.GZIP;
    private int chunkSize = DEFAULT_CHUNK_SIZE;

    private Builder(String host) {
      this.host = host;
    }

    /**
     * Sets the port (default 12201).
     *
     * @param port 1..65535
     * @return this builder
     */
    public Builder port(int port) {
      this.port = port;
      return this;
    }

    /**
     * Sets the compression (default gzip).
     *
     * @param compression compression
     * @return this builder
     */
    public Builder compression(GelfCompression compression) {
      this.compression = compression == null ? GelfCompression.GZIP : compression;
      return this;
    }

    /**
     * Sets the datagram size including the 12-byte chunk header (default 1420).
     *
     * @param chunkSize 64..65507
     * @return this builder
     */
    public Builder chunkSize(int chunkSize) {
      this.chunkSize = chunkSize;
      return this;
    }

    /**
     * Validates and builds the transport; the socket opens on first use.
     *
     * @return the transport
     * @throws ConfigException for a blank host, a bad port or chunk size
     */
    public GelfUdpTransport build() {
      return new GelfUdpTransport(this);
    }
  }
}
