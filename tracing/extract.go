package tracing

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/cloudflare/ebpf_exporter/v2/config"
	"github.com/cloudflare/ebpf_exporter/v2/decoder"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var nilSpanID = "0000000000000000"

func extractLabels(raw []byte, decoders *decoder.Set, config config.Span) ([]string, error) {
	var validDataSize uint
	for _, labelConfig := range config.Labels {
		validDataSize += labelConfig.Size
	}

	decoded, err := decoders.DecodeLabels(raw[:validDataSize], config.Name, config.Labels)
	if err != nil {
		if err != decoder.ErrSkipLabelSet {
			return nil, fmt.Errorf("failed to decode labels: %v", err)
		}

		return nil, err
	}

	return decoded, nil
}

func extractSpan(labels []string, config config.Span) (string, time.Time, time.Duration, trace.TraceID, trace.SpanID, trace.SpanID, []attribute.KeyValue, error) {
	timestamp := time.Now()
	traceID := trace.TraceID{}
	spanID := trace.SpanID{}
	parentID := trace.SpanID{}
	duration := time.Duration(0)
	attributes := []attribute.KeyValue{}

	name := config.Name
	if name == "" {
		name = config.RingBuf
	}

	var err error
	var parsedUint64 uint64

	for i, value := range labels {
		switch config.Labels[i].Name {
		case "span_id":
			// spanID is optional, it is automatically generated if missing
			if value == nilSpanID {
				continue
			}

			spanID, err = trace.SpanIDFromHex(value)
			if err != nil {
				err = fmt.Errorf("error parsing span_id %q: %v", value, err)
			}
		case "trace_id":
			traceID, err = trace.TraceIDFromHex(value)
			if err != nil {
				err = fmt.Errorf("error parsing trace_id %q: %v", value, err)
			}
		case "parent_span_id":
			// parent spanID is optional, it is automatically generated if missing
			if value == nilSpanID {
				continue
			}

			parentID, err = trace.SpanIDFromHex(value)
			if err != nil {
				err = fmt.Errorf("error parsing parent_span_id %q: %v", value, err)
			}
		case "span_monotonic_timestamp_ns":
			parsedUint64, err = strconv.ParseUint(value, 10, 64)
			if err != nil {
				err = fmt.Errorf("error decoding integer for span_monotonic_timestamp_ns from %q: %v", value, err)
			}
			timestamp = ktimeToTime(parsedUint64)
		case "span_duration_ns":
			parsedUint64, err = strconv.ParseUint(value, 10, 64)
			if err != nil {
				err = fmt.Errorf("error decoding integer for span_duration_ns from %q: %v", value, err)
			}
			duration = time.Duration(parsedUint64)
		case "span_name":
			name = value
		default:
			attributes = append(attributes, attribute.String(config.Labels[i].Name, value))
		}

		if err != nil {
			return name, timestamp, duration, traceID, parentID, spanID, attributes, err
		}
	}

	return name, timestamp, duration, traceID, parentID, spanID, attributes, nil
}

func handleDecodedLabels(provider Provider, labels []string, config config.Span) error {
	name, timestamp, duration, traceID, parentID, spanID, attributes, err := extractSpan(labels, config)
	if err != nil {
		return err
	}

	tracer := provider.Tracer(config.Service)

	makeSpan(tracer, name, timestamp, duration, traceID, parentID, spanID, attributes...)

	return nil
}

func makeSpan(tracer trace.Tracer, name string, start time.Time, duration time.Duration, traceID trace.TraceID, parentID trace.SpanID, spanID trace.SpanID, kv ...attribute.KeyValue) {
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     parentID,
		TraceFlags: trace.FlagsSampled,
	})

	ctx := trace.ContextWithSpanContext(context.Background(), spanContext)

	if spanID.IsValid() {
		ctx = context.WithValue(ctx, currentSpanIDKey, spanID)
	}

	_, span := tracer.Start(ctx, name, trace.WithTimestamp(start))

	span.SetAttributes(kv...)

	span.End(trace.WithTimestamp(start.Add(duration)))
}
