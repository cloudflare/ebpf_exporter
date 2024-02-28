package demos

import (
	"github.com/cloudflare/ebpf_exporter/v2/util"
	"go.opentelemetry.io/otel/trace"
)

// PropagationArgs returns traceID split into two big-endian u64 and a big-endian u64 spanID,
// which is the expected format to pass tracing information into the kernel for later decoding
// as hex decoder on the output side.
func PropagationArgs(span trace.Span) (uint64, uint64, uint64) {
	byteOrder := util.GetHostByteOrder()

	spanContext := span.SpanContext()
	traceID := spanContext.TraceID()
	spanID := spanContext.SpanID()

	return byteOrder.Uint64(traceID[0:8]), byteOrder.Uint64(traceID[8:16]), byteOrder.Uint64(spanID[0:8])
}
