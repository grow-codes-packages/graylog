// Command example shows the Graylog Open Go SDK against a real server:
// health and version, a GELF input, a stream, structured logging through
// GELF, and reading the records back with the search API.
//
//	GROW_GRAYLOG_URL=http://127.0.0.1:9000 GROW_GRAYLOG_API_TOKEN=... \
//	GROW_GRAYLOG_GELF_HOST=127.0.0.1 go run .
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	graylog "github.com/grow-codes-packages/graylog/go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := graylog.ConfigFromEnv()
	if err != nil {
		return err // CONFIG error naming the variable, never its value
	}
	fmt.Println("config:", cfg) // credentials print as [REDACTED]

	client, err := graylog.NewClient(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }() // also flushes the log clients

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	health, err := client.Health(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("health: healthy=%t status=%s\n", health.Healthy, health.Status)
	version, err := client.ServerVersion(ctx)
	switch {
	case errors.Is(err, graylog.ErrAuthentication):
		return fmt.Errorf("check GROW_GRAYLOG_API_TOKEN or GROW_GRAYLOG_USER/PASSWORD: %w", err)
	case err != nil:
		return err
	}
	fmt.Println("server version:", version)

	// Make sure a GELF TCP input exists on the configured port.
	input, err := client.EnsureGelfInput(ctx, graylog.GelfTCP, cfg.GelfPortFor(graylog.GelfTCP), graylog.EnsureGelfInputOptions{})
	if err != nil {
		return err
	}
	fmt.Printf("GELF TCP input %s (created=%t)\n", input.ID, input.Created)

	// A stream that routes this example's messages.
	run := fmt.Sprintf("example%d", time.Now().UnixNano())
	streamID, err := client.CreateStream(ctx, graylog.CreateStreamOptions{
		Title: "grow-codes example " + run,
		Rules: []graylog.StreamRule{{Field: "run", Type: graylog.StreamRuleExact, Value: run}},
	})
	if err != nil {
		return err
	}
	defer func() { _ = client.DeleteStream(context.Background(), streamID) }()

	// Structured logging through GELF (secrets are redacted before sending).
	logs, err := client.NewLogClient(graylog.LogOptions{LogClientOptions: graylog.LogClientOptions{
		Resource: map[string]graylog.AttrValue{"service.name": "example", "deployment.environment": "dev"},
	}})
	if err != nil {
		return err
	}
	logger := logs.Logger("example", map[string]graylog.AttrValue{"run": run})
	logger.Info(ctx, "user signed in", "user", "alice", "password", "never-sent")
	logger.Error(ctx, "payment failed", "amount", 12.5)
	if err := logs.Flush(ctx); err != nil {
		return err
	}

	// Read them back: Lucene query, restricted to the new stream.
	records, err := graylog.WaitForLogs(ctx, client.LogQuery(graylog.LogQueryOptions{}), "run:"+run, 2, graylog.WaitForLogOptions{Timeout: time.Minute})
	if err != nil {
		return err
	}
	for _, r := range records {
		fmt.Printf("found: %s %s %v\n", r.SeverityText, r.Body, r.Attributes["user"])
	}
	res, err := client.Search(ctx, "run:"+run, graylog.MessageSearchOptions{Range: 10 * time.Minute, Streams: []string{streamID}})
	if err != nil {
		return err
	}
	fmt.Printf("stream %s holds %d messages\n", streamID, res.Total)
	if len(res.Messages) > 0 {
		m, err := client.GetMessage(ctx, res.Messages[0].Index, res.Messages[0].ID)
		if err != nil {
			return err
		}
		fmt.Println("message source:", m.Fields["source"])
	}
	return nil
}
