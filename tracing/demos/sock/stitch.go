package main

/*
#include <stdint.h>
void
#if defined(__clang__)
__attribute__ ((optnone))
#endif
sock_set_parent_span(int sock_fd, uint64_t trace_id_hi, uint64_t trace_id_lo, uint64_t span_id) { }
*/
import "C"
import (
	"github.com/cloudflare/ebpf_exporter/v2/util"
	"go.opentelemetry.io/otel/trace"
)

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
