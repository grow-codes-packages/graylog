package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.CancelledException;
import codes.grow.packages.graylog.core.ConfigException;
import codes.grow.packages.graylog.core.GraylogException;
import codes.grow.packages.graylog.core.Redaction;
import codes.grow.packages.graylog.core.SdkInfo;
import codes.grow.packages.graylog.core.Secret;
import codes.grow.packages.graylog.core.TimeoutException;
import codes.grow.packages.graylog.core.TlsOptions;
import codes.grow.packages.graylog.core.UnavailableException;
import codes.grow.packages.graylog.core.ValidationException;
import codes.grow.packages.graylog.logging.ExportOptions;
import codes.grow.packages.graylog.logging.ExportResult;
import codes.grow.packages.graylog.logging.LogExporter;
import codes.grow.packages.graylog.logging.LogRecord;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.Proxy;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.GZIPInputStream;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Headers;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

/**
 * The {@link LogExporter} for the Graylog OpenTelemetry (gRPC) input ({@code
 * org.graylog.inputs.otel.OTelGrpcInput}): OTLP {@code LogsService/Export} over gRPC (plaintext
 * HTTP/2 for {@code http://}, TLS for {@code https://}), gzip when the batch asks for it. Graylog
 * Open 7.0 has no OTLP/HTTP input. Graylog stores {@code otel_*} fields; {@link
 * GraylogRecords#fromMessage(Map)} reads them back.
 */
public final class OtlpGrpcLogExporter implements LogExporter {
  private static final MediaType GRPC = MediaType.get("application/grpc");

  private final String endpoint;
  private final OkHttpClient http;
  private final Map<String, String> headers;
  private final List<String> secrets = new ArrayList<>();
  private final AtomicBoolean closed = new AtomicBoolean();

  private OtlpGrpcLogExporter(Builder b) {
    URI u;
    try {
      u = new URI(b.endpoint == null ? "" : b.endpoint);
    } catch (Exception e) {
      throw new ConfigException("otlp: endpoint must be an http(s) URL");
    }
    if (!GraylogConfig.isHttpUrl(b.endpoint)) {
      throw new ConfigException("otlp: endpoint must be an http(s) URL");
    }
    if (b.timeout.isZero()
        || b.timeout.isNegative()
        || b.connectTimeout.isZero()
        || b.connectTimeout.isNegative()) {
      throw new ConfigException("otlp: timeouts must be positive");
    }
    boolean tls = "https".equalsIgnoreCase(u.getScheme());
    this.endpoint = (tls ? "https" : "http") + "://" + u.getRawAuthority();
    OkHttpClient.Builder ob =
        new OkHttpClient.Builder()
            .proxy(Proxy.NO_PROXY)
            .retryOnConnectionFailure(false)
            .connectTimeout(b.connectTimeout)
            .readTimeout(b.timeout)
            .writeTimeout(b.timeout)
            .callTimeout(b.timeout);
    if (tls) {
      ob.protocols(List.of(Protocol.HTTP_2, Protocol.HTTP_1_1));
      TlsOptions t = b.tls;
      t.validate();
      if (t.isCustom()) {
        SSLContext ctx = t.sslContext();
        ob.sslSocketFactory(ctx.getSocketFactory(), platformTrustManager());
        if (t.insecureSkipVerify()) {
          ob.hostnameVerifier((host, session) -> true);
        }
      }
    } else {
      ob.protocols(List.of(Protocol.H2_PRIOR_KNOWLEDGE));
    }
    this.http = ob.build();
    Map<String, String> h = new LinkedHashMap<>();
    b.headers.forEach(
        (k, v) -> {
          h.put(k.toLowerCase(Locale.ROOT), v);
          if (v != null && v.length() >= 4) {
            secrets.add(v);
          }
        });
    if (b.bearerToken != null) {
      h.put("authorization", "Bearer " + b.bearerToken.reveal());
      secrets.add(b.bearerToken.reveal());
    }
    this.headers = Map.copyOf(h);
  }

  static X509TrustManager platformTrustManager() {
    try {
      TrustManagerFactory f =
          TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      f.init((KeyStore) null);
      for (TrustManager tm : f.getTrustManagers()) {
        if (tm instanceof X509TrustManager) {
          return (X509TrustManager) tm;
        }
      }
    } catch (NoSuchAlgorithmException | java.security.KeyStoreException e) {
      throw new ConfigException("otlp: TLS is not available", e);
    }
    throw new ConfigException("otlp: TLS is not available");
  }

  /**
   * Starts a builder.
   *
   * @param endpoint {@code http://host:4317} (plaintext HTTP/2) or {@code https://host:4317} (TLS)
   * @return a new builder (timeout 30 s, connect timeout 10 s)
   */
  public static Builder builder(String endpoint) {
    return new Builder(endpoint);
  }

  /**
   * Returns the endpoint (scheme and authority).
   *
   * @return the endpoint
   */
  public String endpoint() {
    return endpoint;
  }

  /**
   * Frames a protobuf message for gRPC: compressed flag, 4-byte big-endian length, message.
   *
   * @param message the message bytes
   * @param gzip true to gzip the message (flag 1)
   * @return the frame
   */
  static byte[] frame(byte[] message, boolean gzip) {
    byte[] payload = gzip ? GelfIo.compress(GelfCompression.GZIP, message) : message;
    return ByteBuffer.allocate(5 + payload.length)
        .put((byte) (gzip ? 1 : 0))
        .putInt(payload.length)
        .put(payload)
        .array();
  }

  /**
   * Sends records as one {@code ExportLogsServiceRequest}. A partial success counts the rejected
   * records ({@code ValidationException} in the result); transport and gRPC errors fail the future.
   */
  @Override
  public CompletableFuture<ExportResult> export(List<LogRecord> records, ExportOptions options) {
    if (closed.get()) {
      return CompletableFuture.failedFuture(new ConfigException("otlp.export: exporter is closed"));
    }
    if (records.isEmpty()) {
      return CompletableFuture.completedFuture(ExportResult.success(0));
    }
    boolean gzip = options != null && options.gzip();
    Request.Builder rb =
        new Request.Builder()
            .url(endpoint + Otlp.LOGS_EXPORT_PATH)
            .header("te", "trailers")
            .header("user-agent", SdkInfo.userAgent())
            .post(RequestBody.create(frame(Otlp.encodeExportLogsRequest(records), gzip), GRPC));
    if (gzip) {
      rb.header("grpc-encoding", "gzip");
    }
    headers.forEach(rb::header);
    Call call = http.newCall(rb.build());
    AtomicBoolean cancelled = new AtomicBoolean();
    CompletableFuture<ExportResult> result =
        new CompletableFuture<>() {
          @Override
          public boolean cancel(boolean mayInterruptIfRunning) {
            cancelled.set(true);
            call.cancel();
            return super.cancel(mayInterruptIfRunning);
          }
        };
    int n = records.size();
    call.enqueue(
        new Callback() {
          @Override
          public void onFailure(Call c, IOException e) {
            result.completeExceptionally(transportError(cancelled.get(), e));
          }

          @Override
          public void onResponse(Call c, Response response) {
            try (response) {
              result.complete(handle(response, n));
            } catch (GraylogException e) {
              result.completeExceptionally(e);
            } catch (IOException e) {
              result.completeExceptionally(transportError(cancelled.get(), e));
            }
          }
        });
    return result;
  }

  static GraylogException transportError(boolean cancelled, IOException e) {
    if (cancelled) {
      return new CancelledException("otlp.export: cancelled", e);
    }
    // the call timeout cancels the call: OkHttp reports "Canceled" or an InterruptedIOException
    if (e instanceof InterruptedIOException || "Canceled".equals(e.getMessage())) {
      return new TimeoutException("otlp.export: timed out", e);
    }
    String what = e instanceof ConnectException ? "connection failed" : "network error";
    return new UnavailableException(
        "otlp.export: " + what + " (" + e.getClass().getSimpleName() + ")", e);
  }

  ExportResult handle(Response response, int n) throws IOException {
    ResponseBody body = response.body();
    byte[] bytes = body.bytes();
    String status = response.header("grpc-status");
    String message = response.header("grpc-message");
    if (status == null) {
      Headers trailers = response.trailers();
      status = trailers.get("grpc-status");
      message = trailers.get("grpc-message");
    }
    if (response.code() != 200) {
      throw new UnavailableException(
          "otlp.export: unexpected response (HTTP " + response.code() + ")",
          response.code(),
          null,
          null,
          null);
    }
    if (status == null) {
      throw new UnavailableException("otlp.export: response without grpc-status");
    }
    int code;
    try {
      code = Integer.parseInt(status.trim());
    } catch (NumberFormatException e) {
      throw new UnavailableException("otlp.export: invalid grpc-status");
    }
    if (code != 0) {
      throw Otlp.errorForGrpcStatus(code, redact(decodeMessage(message)));
    }
    Otlp.PartialSuccess partial = Otlp.decodePartialSuccess(unframe(bytes));
    long rejected = Math.min(Math.max(partial.rejectedLogRecords(), 0), n);
    if (rejected == 0) {
      return ExportResult.success(n);
    }
    String text = "otlp.export: " + rejected + " records rejected";
    if (!partial.errorMessage().isEmpty()) {
      text += ": " + Redaction.truncate(redact(partial.errorMessage()), Redaction.MAX_VENDOR_TEXT);
    }
    return new ExportResult(
        n - (int) rejected, (int) rejected, Optional.of(new ValidationException(text)));
  }

  static String decodeMessage(String message) {
    if (message == null) {
      return "";
    }
    try {
      return URLDecoder.decode(message.replace("+", "%2B"), StandardCharsets.UTF_8);
    } catch (IllegalArgumentException e) {
      return message;
    }
  }

  private String redact(String text) {
    return Redaction.redactText(text, secrets);
  }

  /** Returns the message of the first gRPC frame (gunzipped when flagged); empty when none. */
  static byte[] unframe(byte[] body) throws IOException {
    if (body.length < 5) {
      return new byte[0];
    }
    ByteBuffer b = ByteBuffer.wrap(body);
    boolean compressed = b.get() == 1;
    int len = b.getInt();
    if (len < 0 || len > body.length - 5) {
      return new byte[0];
    }
    byte[] msg = new byte[len];
    b.get(msg);
    if (!compressed) {
      return msg;
    }
    try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(msg))) {
      return in.readAllBytes();
    }
  }

  /** Releases connections and threads; later exports fail with {@code ConfigException}. */
  @Override
  public CompletableFuture<Void> shutdown() {
    if (closed.compareAndSet(false, true)) {
      http.dispatcher().cancelAll();
      http.dispatcher().executorService().shutdown();
      http.connectionPool().evictAll();
    }
    return CompletableFuture.completedFuture(null);
  }

  @Override
  public String toString() {
    return "OtlpGrpcLogExporter{" + Redaction.redactUrl(endpoint) + "}";
  }

  /** Builder of an {@link OtlpGrpcLogExporter}. */
  public static final class Builder {
    private final String endpoint;
    private Secret bearerToken;
    private final Map<String, String> headers = new LinkedHashMap<>();
    private TlsOptions tls = TlsOptions.defaults();
    private Duration timeout = Duration.ofSeconds(30);
    private Duration connectTimeout = Duration.ofSeconds(10);

    private Builder(String endpoint) {
      this.endpoint = endpoint;
    }

    /**
     * Sets the input's bearer token (sent as {@code authorization: Bearer <token>}).
     *
     * @param token token, {@code null} for none
     * @return this builder
     */
    public Builder bearerToken(Secret token) {
      this.bearerToken = token;
      return this;
    }

    /**
     * Adds a gRPC metadata entry.
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
     * Adds gRPC metadata entries.
     *
     * @param headers entries ({@code null} is ignored)
     * @return this builder
     */
    public Builder headers(Map<String, String> headers) {
      if (headers != null) {
        this.headers.putAll(headers);
      }
      return this;
    }

    /**
     * Sets the TLS options of {@code https} endpoints.
     *
     * @param tls options
     * @return this builder
     */
    public Builder tls(TlsOptions tls) {
      this.tls = tls == null ? TlsOptions.defaults() : tls;
      return this;
    }

    /**
     * Sets the deadline of one export call (default 30 s).
     *
     * @param timeout positive duration
     * @return this builder
     */
    public Builder timeout(Duration timeout) {
      this.timeout = timeout == null ? Duration.ofSeconds(30) : timeout;
      return this;
    }

    /**
     * Sets the connect timeout (default 10 s).
     *
     * @param timeout positive duration
     * @return this builder
     */
    public Builder connectTimeout(Duration timeout) {
      this.connectTimeout = timeout == null ? Duration.ofSeconds(10) : timeout;
      return this;
    }

    /**
     * Validates and builds the exporter; the connection opens on first export.
     *
     * @return the exporter
     * @throws ConfigException for a bad endpoint, timeouts or TLS settings
     */
    public OtlpGrpcLogExporter build() {
      return new OtlpGrpcLogExporter(this);
    }
  }
}
