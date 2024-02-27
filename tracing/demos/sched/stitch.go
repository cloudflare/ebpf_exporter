package main

/*
#include <stdint.h>
#include <sys/sdt.h>

void sched_set_parent_span(uint64_t trace_id_hi, uint64_t trace_id_lo, uint64_t span_id)
{
	DTRACE_PROBE3(ebpf_exporter, sched_set_parent_span, trace_id_hi, trace_id_lo, span_id);
}

void sched_clear_parent_span()
{
	DTRACE_PROBE(ebpf_exporter, sched_clear_parent_span);
}
*/
import "C"
import (
	"github.com/cloudflare/ebpf_exporter/v2/util"
	"go.opentelemetry.io/otel/trace"
)

func schedSetParentSpan(span trace.Span) {
	byteOrder := util.GetHostByteOrder()

	traceID := span.SpanContext().TraceID()
	spanID := span.SpanContext().SpanID()

	C.sched_set_parent_span(
		C.uint64_t(byteOrder.Uint64(traceID[0:8])),
		C.uint64_t(byteOrder.Uint64(traceID[8:16])),
		C.uint64_t(byteOrder.Uint64(spanID[0:8])),
	)
}

func schedClearParentSpan() {
	C.sched_clear_parent_span()
}
