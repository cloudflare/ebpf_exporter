package main

/*
#include <stdint.h>
#include <sys/sdt.h>

void cfs_set_parent_span(uint64_t trace_id_hi, uint64_t trace_id_lo, uint64_t span_id)
{
	DTRACE_PROBE3(ebpf_exporter, cfs_set_parent_span, trace_id_hi, trace_id_lo, span_id);
}

void cfs_clear_parent_span()
{
	DTRACE_PROBE(ebpf_exporter, cfs_clear_parent_span);
}
*/
import "C"
import (
	"github.com/cloudflare/ebpf_exporter/v2/util"
	"go.opentelemetry.io/otel/trace"
)

func cfsSetParentSpan(span trace.Span) {
	byteOrder := util.GetHostByteOrder()

	traceID := span.SpanContext().TraceID()
	spanID := span.SpanContext().SpanID()

	C.cfs_set_parent_span(
		C.uint64_t(byteOrder.Uint64(traceID[0:8])),
		C.uint64_t(byteOrder.Uint64(traceID[8:16])),
		C.uint64_t(byteOrder.Uint64(spanID[0:8])),
	)
}

func cfsClearParentSpan() {
	C.cfs_clear_parent_span()
}
