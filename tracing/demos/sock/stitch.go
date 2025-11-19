package main

/*
#include <stdint.h>
#include <sys/sdt.h>

void sock_set_parent_span(uint64_t socket_cookie, uint64_t trace_id_hi, uint64_t trace_id_lo, uint64_t span_id, uint64_t example_userspace_tag)
{
	DTRACE_PROBE5(ebpf_exporter, sock_set_parent_span, socket_cookie, trace_id_hi, trace_id_lo, span_id, example_userspace_tag);
}
*/
import "C"
import (
	"github.com/cloudflare/ebpf_exporter/v2/tracing/demos"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"
)

func sockSentParentSpan(fd uintptr, span trace.Span) {
	traceIDHi, traceIDLo, spanID := demos.PropagationArgs(span)

	cookie, err := unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		panic(err)
	}

	C.sock_set_parent_span(
		C.uint64_t(cookie),
		C.uint64_t(traceIDHi),
		C.uint64_t(traceIDLo),
		C.uint64_t(spanID),
		C.uint64_t(666),
	)
}
