// Package graylog is the Grow Codes SDK for Graylog Open.
//
// Create a client from the environment (GROW_GRAYLOG_URL,
// GROW_GRAYLOG_TOKEN, ...) or from a Config literal:
//
//	client, err := graylog.NewClientFromEnv()
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//	status, err := client.Health(ctx)
//
// Every error is an *Error; compare codes with errors.Is against the Err*
// sentinels (errors.Is(err, graylog.ErrNotFound)). Credentials are wrapped in
// Secret and never appear in errors, hooks or logs.
//
// Graylog Open is a trademark of Graylog, Inc.. This package is not affiliated
// with or endorsed by Graylog, Inc..
package graylog
