package demos

import (
	"os"

	"github.com/cloudflare/ebpf_exporter/v2/tracing"
	"go.opentelemetry.io/otel/sdk/trace"
)

// SetupTracing sets up tracing for demos
func SetupTracing() (trace.SpanProcessor, error) {
	// Save the trouble of passing these externally
	defaultEnv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	defaultEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
	defaultEnv("OTEL_TRACES_SAMPLER", "always_on")
	defaultEnv("OTEL_SERVICE_NAME", "demo")

	return tracing.NewProcessor()
}

// defaultEnv sets the default value for an env variable it is not explicitly set
func defaultEnv(key, value string) {
	if os.Getenv(key) == "" {
		os.Setenv(key, value)
	}
}
