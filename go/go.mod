module github.com/grow-codes-packages/graylog/go

go 1.26

// Dependencies are added per category by sdk-kit; "make deps" runs "go mod tidy"
// to complete the require list and write go.sum.

require go.opentelemetry.io/otel v1.47.0

require go.opentelemetry.io/otel/trace v1.47.0
require go.uber.org/zap v1.28.0
