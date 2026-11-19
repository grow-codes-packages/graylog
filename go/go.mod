module github.com/grow-codes-packages/graylog/go

go 1.26.0

// Dependencies are added per category by sdk-kit; "make deps" runs "go mod tidy"
// to complete the require list and write go.sum.

require go.opentelemetry.io/otel v1.47.0 // indirect

require go.opentelemetry.io/otel/trace v1.47.0

require (
	go.opentelemetry.io/proto/otlp v1.11.1
	go.uber.org/zap v1.28.0
	google.golang.org/grpc v1.85.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.31.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260928230214-8a89bd6388cc // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260928230214-8a89bd6388cc // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
