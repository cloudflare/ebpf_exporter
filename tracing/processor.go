package tracing

import (
	"context"

	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/trace"
)

// NewProcessor returns an OpenTelemetry span processor configured with autoexport env variables
func NewProcessor() (trace.SpanProcessor, error) {
	exporter, err := autoexport.NewSpanExporter(context.Background())
	if err != nil {
		return nil, err
	}

	processor := trace.NewBatchSpanProcessor(exporter)
	otel.SetTracerProvider(trace.NewTracerProvider(trace.WithSpanProcessor(processor)))

	return processor, nil
}
