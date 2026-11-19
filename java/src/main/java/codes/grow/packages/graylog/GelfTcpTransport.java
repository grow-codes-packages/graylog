package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.CancelledException;
import codes.grow.packages.graylog.core.ConfigException;
import codes.grow.packages.graylog.core.RetryPolicy;
import codes.grow.packages.graylog.core.TlsOptions;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * GELF over TCP: NUL-terminated JSON frames over one long-lived connection (input option {@code
 * use_null_delimiter}). Batches never interleave. A connection closed by the server is detected
 * before each batch and re-opened; a failed batch is re-sent on a new connection up to {@code
 * retry.maxRetries()} times with full-jitter backoff (at-least-once). TLS is optional.
 */
public final class GelfTcpTransport implements GelfTransport {
  /** Sleeps between reconnect attempts; replaced in tests. */
  interface Sleeper {
    void sleep(Duration d) throws InterruptedException;
  }

  private final String host;
  private final int port;
  private final SSLSocketFactory sslFactory;
  private final String serverName;
  private final boolean verifyHostname;
  private final Duration connectTimeout;
  private final Duration writeTimeout;
  private final RetryPolicy retry;
  Sleeper sleeper = d -> TimeUnit.NANOSECONDS.sleep(d.toNanos());

  private Socket socket;
  private boolean closed;
  private int connections;

  private GelfTcpTransport(Builder b) {
    this.host = GelfIo.checkHostPort("gelf.tcp", b.host, b.port);
    this.port = b.port;
    if (b.connectTimeout.isZero()
        || b.connectTimeout.isNegative()
        || b.writeTimeout.isZero()
        || b.writeTimeout.isNegative()) {
      throw new ConfigException("gelf.tcp: timeouts must be positive");
    }
    this.connectTimeout = b.connectTimeout;
    this.writeTimeout = b.writeTimeout;
    this.retry = b.retry;
    this.serverName = b.serverName != null ? b.serverName : b.host;
    if (b.tls) {
      TlsOptions t = b.tlsOptions;
      t.validate();
      SSLContext ctx;
      try {
        ctx = t.isCustom() ? t.sslContext() : SSLContext.getDefault();
      } catch (NoSuchAlgorithmException e) {
        throw new ConfigException("gelf.tcp: TLS is not available", e);
      }
      this.sslFactory = ctx.getSocketFactory();
      this.verifyHostname = !t.insecureSkipVerify();
    } else {
      this.sslFactory = null;
      this.verifyHostname = false;
    }
  }

  /**
   * Starts a builder.
   *
   * @param host host of the GELF TCP input
   * @return a new builder (port 12201, no TLS, connect 10 s, write 30 s, default retries)
   */
  public static Builder builder(String host) {
    return new Builder(host);
  }

  @Override
  public GelfProtocol protocol() {
    return GelfProtocol.TCP;
  }

  /**
   * Returns whether the transport uses TLS.
   *
   * @return true with TLS
   */
  public boolean secure() {
    return sslFactory != null;
  }

  /**
   * Returns the number of connections opened so far (diagnostics).
   *
   * @return the count
   */
  public synchronized int connections() {
    return connections;
  }

  /**
   * Encodes messages as NUL-terminated JSON frames.
   *
   * @param messages messages
   * @return the frames
   */
  public static byte[] frame(List<GelfMessage> messages) {
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    for (GelfMessage m : messages) {
      buf.writeBytes(m.encode());
      buf.write(0);
    }
    return buf.toByteArray();
  }

  /** Writes all messages as NUL-terminated frames in one write, reconnecting when needed. */
  @Override
  public synchronized GelfSendResult send(List<GelfMessage> messages, GelfSendOptions options) {
    GelfIo.requireMessages("gelf.tcp", messages);
    if (closed) {
      throw GelfIo.closed("gelf.tcp");
    }
    if (messages.isEmpty()) {
      return GelfSendResult.ofSent(0);
    }
    byte[] data = frame(messages);
    for (int attempt = 0; ; attempt++) {
      if (Thread.currentThread().isInterrupted()) {
        throw new CancelledException("gelf.tcp: cancelled (thread interrupted)");
      }
      try {
        write(data);
        return GelfSendResult.ofSent(messages.size());
      } catch (IOException e) {
        if (attempt >= retry.maxRetries()) {
          throw GelfIo.networkError("gelf.tcp", e);
        }
      }
      try {
        sleeper.sleep(retry.backoff(attempt));
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new CancelledException("gelf.tcp: cancelled (thread interrupted)", e);
      }
    }
  }

  private void write(byte[] data) throws IOException {
    if (socket != null && !alive(socket)) {
      dropSocket();
    }
    if (socket == null) {
      socket = connect();
      connections++;
    }
    Socket s = socket;
    AtomicBoolean fired = new AtomicBoolean();
    ScheduledFuture<?> watchdog =
        GelfIo.SCHEDULER.schedule(
            () -> {
              fired.set(true);
              closeQuietly(s);
            },
            writeTimeout.toNanos(),
            TimeUnit.NANOSECONDS);
    try {
      s.getOutputStream().write(data);
      s.getOutputStream().flush();
    } catch (IOException e) {
      dropSocket();
      if (fired.get()) {
        throw new SocketTimeoutException("write timed out");
      }
      throw e;
    } finally {
      watchdog.cancel(false);
    }
  }

  private Socket connect() throws IOException {
    Socket raw = new Socket();
    try {
      raw.setKeepAlive(true);
      raw.setTcpNoDelay(true);
      raw.connect(new InetSocketAddress(host, port), (int) Math.max(1, connectTimeout.toMillis()));
      if (sslFactory == null) {
        return raw;
      }
      SSLSocket ssl = (SSLSocket) sslFactory.createSocket(raw, serverName, port, true);
      SSLParameters params = ssl.getSSLParameters();
      if (verifyHostname) {
        params.setEndpointIdentificationAlgorithm("HTTPS");
      }
      if (!serverName.isEmpty() && Character.isLetter(serverName.charAt(0))) {
        params.setServerNames(List.of(new SNIHostName(serverName)));
      }
      ssl.setSSLParameters(params);
      ssl.setSoTimeout((int) Math.max(1, connectTimeout.toMillis()));
      ssl.startHandshake();
      ssl.setSoTimeout(0);
      return ssl;
    } catch (IOException | RuntimeException e) {
      closeQuietly(raw);
      throw e instanceof IOException ? (IOException) e : new IOException(e.getMessage(), e);
    }
  }

  /**
   * Reports whether the connection is still open: Graylog never writes on a GELF TCP connection, so
   * a read that does not time out means EOF or a reset.
   */
  static boolean alive(Socket s) {
    try {
      s.setSoTimeout(1);
      InputStream in = s.getInputStream();
      int b = in.read();
      return b >= 0;
    } catch (SocketTimeoutException e) {
      return true;
    } catch (IOException e) {
      return false;
    } finally {
      try {
        s.setSoTimeout(0);
      } catch (IOException ignored) {
        // the socket is gone; the next write reconnects
      }
    }
  }

  private void dropSocket() {
    if (socket != null) {
      closeQuietly(socket);
      socket = null;
    }
  }

  private static void closeQuietly(Socket s) {
    try {
      s.close();
    } catch (IOException ignored) {
      // best effort
    }
  }

  /** Closes the connection. Idempotent. */
  @Override
  public synchronized void close() {
    closed = true;
    dropSocket();
  }

  @Override
  public String toString() {
    return "GelfTcpTransport{" + host + ":" + port + (secure() ? ", tls" : "") + "}";
  }

  /** Builder of a {@link GelfTcpTransport}. */
  public static final class Builder {
    private final String host;
    private int port = GraylogConfig.DEFAULT_GELF_PORT;
    private boolean tls;
    private TlsOptions tlsOptions = TlsOptions.defaults();
    private String serverName;
    private Duration connectTimeout = Duration.ofSeconds(10);
    private Duration writeTimeout = Duration.ofSeconds(30);
    private RetryPolicy retry = RetryPolicy.defaults();

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
     * Enables TLS (the input needs {@code tls_enable}).
     *
     * @param tls true to enable
     * @return this builder
     */
    public Builder tls(boolean tls) {
      this.tls = tls;
      return this;
    }

    /**
     * Sets the TLS options (CA bundle, client certificate, {@code insecureSkipVerify}).
     *
     * @param options TLS options
     * @return this builder
     */
    public Builder tlsOptions(TlsOptions options) {
      this.tlsOptions = options == null ? TlsOptions.defaults() : options;
      return this;
    }

    /**
     * Overrides the SNI / verification host name (default: the host).
     *
     * @param serverName name
     * @return this builder
     */
    public Builder serverName(String serverName) {
      this.serverName = serverName;
      return this;
    }

    /**
     * Sets the connect timeout (default 10 s).
     *
     * @param d positive duration
     * @return this builder
     */
    public Builder connectTimeout(Duration d) {
      this.connectTimeout = d == null ? Duration.ofSeconds(10) : d;
      return this;
    }

    /**
     * Sets the write timeout of one batch (default 30 s).
     *
     * @param d positive duration
     * @return this builder
     */
    public Builder writeTimeout(Duration d) {
      this.writeTimeout = d == null ? Duration.ofSeconds(30) : d;
      return this;
    }

    /**
     * Sets the reconnect policy (default {@link RetryPolicy#defaults()}).
     *
     * @param retry policy
     * @return this builder
     */
    public Builder retry(RetryPolicy retry) {
      this.retry = retry == null ? RetryPolicy.defaults() : retry;
      return this;
    }

    /**
     * Validates and builds the transport; the connection opens on first use.
     *
     * @return the transport
     * @throws ConfigException for a blank host, a bad port, timeouts or TLS settings
     */
    public GelfTcpTransport build() {
      return new GelfTcpTransport(this);
    }
  }
}
