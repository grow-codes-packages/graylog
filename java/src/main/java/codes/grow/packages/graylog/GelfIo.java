package codes.grow.packages.graylog;

import codes.grow.packages.graylog.core.ConfigException;
import codes.grow.packages.graylog.core.GraylogException;
import codes.grow.packages.graylog.core.TimeoutException;
import codes.grow.packages.graylog.core.UnavailableException;
import codes.grow.packages.graylog.core.ValidationException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;

/** Shared helpers of the GELF transports. */
final class GelfIo {
  private static final AtomicInteger THREADS = new AtomicInteger();

  /** Daemon threads for blocking sends behind the async APIs. */
  static final ExecutorService EXECUTOR = Executors.newCachedThreadPool(GelfIo::daemon);

  /** Daemon scheduler for write watchdogs. */
  static final ScheduledExecutorService SCHEDULER =
      Executors.newSingleThreadScheduledExecutor(GelfIo::daemon);

  private GelfIo() {}

  private static Thread daemon(Runnable r) {
    Thread t = new Thread(r, "grow-graylog-gelf-" + THREADS.incrementAndGet());
    t.setDaemon(true);
    return t;
  }

  static byte[] compress(GelfCompression c, byte[] payload) {
    if (c == GelfCompression.NONE) {
      return payload;
    }
    ByteArrayOutputStream buf = new ByteArrayOutputStream(payload.length / 2 + 32);
    try (OutputStream w =
        c == GelfCompression.GZIP ? new GZIPOutputStream(buf) : new DeflaterOutputStream(buf)) {
      w.write(payload);
    } catch (IOException e) {
      throw new UncheckedIOException(e); // in-memory streams never fail
    }
    return buf.toByteArray();
  }

  static String checkHostPort(String op, String host, int port) {
    if (host == null || host.isBlank()) {
      throw new ConfigException(op + ": host must not be blank");
    }
    if (port < 1 || port > 65535) {
      throw new ConfigException(op + ": port must be an integer 1..65535");
    }
    return host;
  }

  static GraylogException networkError(String op, IOException e) {
    if (e instanceof SocketTimeoutException) {
      return new TimeoutException(op + ": timeout", e);
    }
    return new UnavailableException(
        op + ": network error (" + e.getClass().getSimpleName() + ")", e);
  }

  static ConfigException closed(String op) {
    return new ConfigException(op + ": transport is closed");
  }

  static void requireMessages(String op, List<GelfMessage> messages) {
    if (messages == null) {
      throw new ValidationException(op + ": messages must not be null");
    }
    for (GelfMessage m : messages) {
      if (m == null) {
        throw new ValidationException(op + ": message is null");
      }
    }
  }
}
