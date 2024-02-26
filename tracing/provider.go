package tracing

import (
	"os"
	"reflect"
	"sync"

	"go.opentelemetry.io/otel/sdk/resource"
	sdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

// Provider creates tracers for requested service names
type Provider interface {
	Tracer(service string) trace.Tracer
}

type provider struct {
	mu        sync.Mutex
	processor sdk.SpanProcessor
	providers map[string]*sdk.TracerProvider
}

// NewProvider creates a provider with a specified processor
func NewProvider(processor sdk.SpanProcessor) Provider {
	return &provider{processor: processor, providers: map[string]*sdk.TracerProvider{}}
}

// Tracer creates a new Tracer instance with a specified service name
func (p *provider) Tracer(service string) trace.Tracer {
	if service == "" {
		service = os.Getenv("OTEL_SERVICE_NAME")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.providers[service]; !ok {
		p.providers[service] = sdk.NewTracerProvider(
			sdk.WithSampler(sdk.AlwaysSample()),
			sdk.WithResource(resource.NewWithAttributes("", semconv.ServiceNameKey.String(service))),
			sdk.WithSpanProcessor(p.processor),
			sdk.WithIDGenerator(newPredeterminedIDGenerator()),
		)
	}

	return p.providers[service].Tracer(reflect.TypeOf(currentSpanIDKey).PkgPath())
}
