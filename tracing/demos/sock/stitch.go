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
	"github.com/cloudflare/ebpf_exporter/v2/util"
	"go.opentelemetry.io/otel/trace"
)

func enableKernelTracing() {
	C.enable_kernel_tracing()
}

func sockSentParentSpan(fd uintptr, span trace.Span) {
	byteOrder := util.GetHostByteOrder()

	traceID := span.SpanContext().TraceID()
	spanID := span.SpanContext().SpanID()

	C.sock_set_parent_span(
		C.int(fd),
		C.uint64_t(byteOrder.Uint64(traceID[0:8])),
		C.uint64_t(byteOrder.Uint64(traceID[8:16])),
		C.uint64_t(byteOrder.Uint64(spanID[0:8])),
	)
}
