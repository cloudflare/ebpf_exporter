package tracing

import (
	"reflect"
	"testing"
	"time"

	"github.com/cloudflare/ebpf_exporter/v2/config"
	"github.com/cloudflare/ebpf_exporter/v2/decoder"
	"github.com/cloudflare/ebpf_exporter/v2/util"
	"go.opentelemetry.io/otel/attribute"
)

func TestExtractEmpty(t *testing.T) {
	config := config.Span{RingBuf: "some_buf"}

	name, timestamp, duration, traceID, parentID, spanID, attributes, err := extractSpan([]string{}, config)
	if err != nil {
		t.Errorf("Error extracting span from empty labels: %v", err)
	}

	if name != config.RingBuf {
		t.Errorf("Expected name %q to match ringbuf name %q", name, config.RingBuf)
	}

	timeDiff := time.Since(timestamp)
	if timeDiff.Abs().Milliseconds() > 1 {
		t.Errorf("Expected time difference to be negligible, got %v", timeDiff)
	}

	if duration != 0 {
		t.Errorf("Expected duration to be zero, got %v", duration)
	}

	if traceID.IsValid() {
		t.Errorf("Expected empty traceID, got %q", traceID.String())
	}

	if parentID.IsValid() {
		t.Errorf("Expected empty parent spanID, got %q", parentID.String())
	}

	if spanID.IsValid() {
		t.Errorf("Expected empty spanID, got %q", spanID.String())
	}

	if len(attributes) > 0 {
		t.Errorf("Expected no attributes, got %#v", attributes)
	}
}

func TestExtractFilled(t *testing.T) {
	byteOrder := util.GetHostByteOrder()

	// ktime 1 minute into the future
	ktimeBuf := make([]byte, 8)
	byteOrder.PutUint64(ktimeBuf, ktime()+60*1000000000)

	cases := []struct {
		in         []byte
		config     config.Span
		name       string
		timestamp  time.Time
		duration   time.Duration
		traceID    string
		parentID   string
		spanID     string
		attributes []attribute.KeyValue
	}{
		{
			in: append(
				append(
					[]byte{
						0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xed, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // trace_id
						0xfe, 0xed, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // parent_span_id
						0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // span_id
					},
					ktimeBuf..., // span_monotonic_timestamp_ns
				),
				[]byte{
					0xff, 0xab, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, // span_duration_ns
					0x68, 0x61, 0x68, 0x61, // lol
				}...,
			),
			config: config.Span{
				Name: "potato",
				Labels: []config.Label{
					{
						Name: "trace_id",
						Size: 16,
						Decoders: []config.Decoder{
							{
								Name: "hex",
							},
						},
					},
					{
						Name: "parent_span_id",
						Size: 8,
						Decoders: []config.Decoder{
							{
								Name: "hex",
							},
						},
					},
					{
						Name: "span_id",
						Size: 8,
						Decoders: []config.Decoder{
							{
								Name: "hex",
							},
						},
					},
					{
						Name: "span_monotonic_timestamp_ns",
						Size: 8,
						Decoders: []config.Decoder{
							{
								Name: "uint",
							},
						},
					},
					{
						Name: "span_duration_ns",
						Size: 8,
						Decoders: []config.Decoder{
							{
								Name: "uint",
							},
						},
					},
					{
						Name: "lol",
						Size: 4,
						Decoders: []config.Decoder{
							{
								Name: "string",
							},
						},
					},
				},
			},
			name:       "potato",
			timestamp:  time.Now().Add(time.Minute),
			traceID:    "beef000000000000feed000000000000",
			parentID:   "feed000000000000",
			spanID:     "beef000000000000",
			duration:   time.Duration(4041727),
			attributes: []attribute.KeyValue{attribute.String("lol", "haha")},
		},
	}

	decoders, err := decoder.NewSet(nil)
	if err != nil {
		t.Fatalf("Error creating decoders set: %v", err)
	}

	for i, c := range cases {
		labels, err := extractLabels(c.in, decoders, c.config)
		if err != nil {
			t.Errorf("Error extracting labels from %#v: %v", c.in, err)
			continue
		}

		name, timestamp, duration, traceID, parentID, spanID, attributes, err := extractSpan(labels, c.config)
		if err != nil {
			t.Errorf("Error extracting span from labels for %d: %v", i, err)
		}

		if name != c.name {
			t.Errorf("Expected name %q, got %q for %d", c.name, name, i)
		}

		timeDiff := timestamp.Sub(c.timestamp)
		if timeDiff.Abs().Milliseconds() > 1 {
			t.Errorf("Expected negligible time difference, got %q (timestamp %q expected, got %q) for %d", timeDiff.String(), c.timestamp.Format(time.RFC3339Nano), timestamp.Format(time.RFC3339Nano), i)
		}

		if duration != c.duration {
			t.Errorf("Expected duration %dns, got %dns for %d / %v", c.duration.Nanoseconds(), duration.Nanoseconds(), i, labels)
		}

		if traceID.String() != c.traceID {
			t.Errorf("Expected traceID %q, got %q for %d", c.traceID, traceID.String(), i)
		}

		if parentID.String() != c.parentID {
			t.Errorf("Expected parent spanID %q, got %q for %d", c.parentID, parentID.String(), i)
		}

		if spanID.String() != c.spanID {
			t.Errorf("Expected spanID %q, got %q for %d", c.spanID, spanID.String(), i)
		}

		if !reflect.DeepEqual(attributes, c.attributes) {
			t.Errorf("Expected attributes %#v, got %#v for %d", c.attributes, attributes, i)
		}
	}
}
