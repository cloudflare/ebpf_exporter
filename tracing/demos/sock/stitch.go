package main

/*
#include <stdint.h>
#include <sys/sdt.h>

void enable_kernel_tracing()
{
	DTRACE_PROBE(ebpf_exporter, enable_kernel_tracing);
}

void sock_set_parent_span(int sock_fd, uint64_t trace_id_hi, uint64_t trace_id_lo, uint64_t span_id)
{
	DTRACE_PROBE4(ebpf_exporter, sock_set_parent_span, sock_fd, trace_id_hi, trace_id_lo, span_id);
}
*/
import "C"
import (
	"github.com/cloudflare/ebpf_exporter/v2/tracing/demos"
	"go.opentelemetry.io/otel/trace"
)

func enableKernelTracing() {
	C.enable_kernel_tracing()
}

func sockSentParentSpan(fd uintptr, span trace.Span) {
	traceIDHi, traceIDLo, spanID := demos.PropagationArgs(span)

	C.sock_set_parent_span(
		C.int(fd),
		C.uint64_t(traceIDHi),
		C.uint64_t(traceIDLo),
		C.uint64_t(spanID),
	)
}
