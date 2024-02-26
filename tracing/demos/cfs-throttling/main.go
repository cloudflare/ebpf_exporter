package main

import (
	"context"
	"crypto/sha512"
	"log"
	"os"
	"time"

	"github.com/cloudflare/ebpf_exporter/v2/tracing/demos"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func main() {
	processor, err := demos.SetupTracing()
	if err != nil {
		log.Fatalf("Error setting up tracing: %v", err)
	}

	tracer := otel.Tracer("")

	ctx, workSpan := tracer.Start(context.Background(), "work", trace.WithAttributes(attribute.Int("tgid", os.Getpid())))

	_, busySpan := tracer.Start(ctx, "busy")
	busySpan.SetAttributes(attribute.Bool("kerne.traced", true))

	cfsSetParentSpan(busySpan)

	iterations := busyWork()

	busySpan.SetAttributes(attribute.Int("iterations", iterations))

	cfsClearParentSpan()

	busySpan.End()

	_, anotherBusySpan := tracer.Start(ctx, "busy")
	anotherBusySpan.SetAttributes(attribute.Bool("kerne.traced", false))

	moreIterations := busyWork()

	anotherBusySpan.SetAttributes(attribute.Int("iterations", moreIterations))

	anotherBusySpan.End()

	workSpan.End()

	err = processor.ForceFlush(context.Background())
	if err != nil {
		log.Fatalf("Error flushing spans: %v", err)
	}
}

func busyWork() int {
	started := time.Now()
	sum := sha512.New()
	for i := 0; ; i++ {
		sum.Sum([]byte("brrr"))

		if i%1000 == 0 && time.Since(started).Milliseconds() > 1000 {
			return i
		}
	}
}
