package main

import (
	"context"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/cloudflare/ebpf_exporter/v2/tracing/demos"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func main() {
	// Keep the number of events reasonable
	runtime.GOMAXPROCS(1)

	processor, err := demos.SetupTracing()
	if err != nil {
		log.Fatalf("Error setting up tracing: %v", err)
	}

	tracer := otel.Tracer("")

	ctx, lifetimeSpan := tracer.Start(context.Background(), "lifetime", trace.WithAttributes(attribute.Int("tgid", os.Getpid())))

	_, tracedSpan := tracer.Start(ctx, "traced sleep")

	schedSetParentSpan(tracedSpan)

	time.Sleep(time.Millisecond * 123)

	schedClearParentSpan()

	tracedSpan.End()

	_, nonTracedSpan := tracer.Start(ctx, "non-traced sleep")

	time.Sleep(time.Millisecond * 123)

	nonTracedSpan.End()

	lifetimeSpan.End()

	err = processor.ForceFlush(context.Background())
	if err != nil {
		log.Fatalf("Error flushing spans: %v", err)
	}
}
