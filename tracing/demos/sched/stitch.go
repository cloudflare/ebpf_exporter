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
	"github.com/cloudflare/ebpf_exporter/v2/tracing/demos"
	"go.opentelemetry.io/otel/trace"
)

func schedSetParentSpan(span trace.Span) {
	traceIDHi, traceIDLo, spanID := demos.PropagationArgs(span)

	C.sched_set_parent_span(
		C.uint64_t(traceIDHi),
		C.uint64_t(traceIDLo),
		C.uint64_t(spanID),
	)
}

func schedClearParentSpan() {
	C.sched_clear_parent_span()
}
