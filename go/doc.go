// Package graylog is the Grow Codes SDK for Graylog Open: REST admin and
// search, GELF ingest over UDP, TCP and HTTP, an optional OTLP/gRPC log
// exporter, and the shared logging API (LogClient, Logger, slog handler,
// LogQueryClient).
//
// Create a client from the environment (GROW_GRAYLOG_URL,
// GROW_GRAYLOG_API_TOKEN or GROW_GRAYLOG_USER/GROW_GRAYLOG_PASSWORD,
// GROW_GRAYLOG_GELF_HOST, … with GRAYLOG_* fallbacks) or from a Config literal:
//
//	client, err := graylog.NewClientFromEnv()
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//	status, err := client.Health(ctx)
//
// Send logs through GELF (TCP by default) and read them back:
//
//	logs, err := client.NewLogClient(graylog.LogOptions{})
//	logs.Logger("api", nil).Info(ctx, "user signed in", "user", "alice")
//	_ = logs.Flush(ctx)
//	rec, err := client.LogQuery(graylog.LogQueryOptions{}).WaitForLog(ctx, "user:alice", graylog.WaitForLogOptions{})
//
// Every error is an *Error; compare codes with errors.Is against the Err*
// sentinels (errors.Is(err, graylog.ErrNotFound)). Credentials are wrapped in
// Secret and never appear in errors, hooks or logs.
//
// Graylog is a trademark of Graylog, Inc. This package is not affiliated with
// or endorsed by Graylog, Inc.
package graylog
