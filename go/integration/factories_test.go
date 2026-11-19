package integration

import (
	"context"
	"strings"
	"testing"

	graylog "github.com/grow-codes-packages/graylog/go"
	"github.com/grow-codes-packages/graylog/go/testkit"
)

// capabilities the deployment under test offers (see conformance "requires").
// Graylog serves search (Views API), a polling tail, streams, field names
// (labels) and the server version.
var capabilities = []string{"version", "query", "tail", "labels", "streams"}

// categories runs "core" plus this service's categories.
func categories() []string {
	return append([]string{"core"}, strings.Split("logging", ",")...)
}

// factories builds the conformance targets: core → *graylog.Client, logging →
// a batching LogClient over GELF TCP (the configured protocol) plus the
// LogQuery client.
func factories(t *testing.T) testkit.Factories {
	t.Helper()
	return testkit.Factories{
		"core": testkit.CoreFactory(func(context.Context) (testkit.CoreTarget, error) {
			return graylog.NewClientFromEnv()
		}),
		"logging": func(ctx context.Context, env *testkit.Env) (any, error) {
			c, err := graylog.NewClientFromEnv()
			if err != nil {
				return nil, err
			}
			env.AddCleanup(func() { _ = c.Close() })
			return testkit.LoggingFactory(func(_ context.Context, opts graylog.BatchOptions) (testkit.LoggingTarget, error) {
				lc, err := c.NewLogClient(graylog.LogOptions{LogClientOptions: graylog.LogClientOptions{
					Batch:    opts,
					Resource: map[string]graylog.AttrValue{"service.name": env.ServiceName, "deployment.environment": "conformance"},
				}})
				if err != nil {
					return testkit.LoggingTarget{}, err
				}
				return testkit.LoggingTarget{Client: lc, Query: c.LogQuery(graylog.LogQueryOptions{})}, nil
			})(ctx, env)
		},
	}
}
