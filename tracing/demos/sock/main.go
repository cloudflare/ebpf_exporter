package main

import (
	"context"
	"io"
	"log"
	"net"
	"syscall"

	"github.com/cloudflare/ebpf_exporter/v2/tracing/demos"
	"go.opentelemetry.io/otel"
)

func main() {
	enableKernelTracing()

	processor, err := demos.SetupTracing()
	if err != nil {
		log.Fatalf("Error setting up tracing: %v", err)
	}

	tracer := otel.Tracer("")

	connFd := uintptr(0)

	ctx, connSpan := tracer.Start(context.Background(), "connection")

	_, dialSpan := tracer.Start(ctx, "dial")

	dialer := net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				sockSentParentSpan(fd, dialSpan)
				connFd = fd
			})
		},
	}

	conn, err := dialer.Dial("tcp", "example.com:80")
	if err != nil {
		log.Fatalf("Error dialing: %v", err)
	}

	dialSpan.End()

	_, writeSpan := tracer.Start(ctx, "write")

	sockSentParentSpan(connFd, writeSpan)

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
	if err != nil {
		log.Printf("Error writing request: %v", err)
	}

	writeSpan.End()

	_, readSpan := tracer.Start(ctx, "read")

	sockSentParentSpan(connFd, readSpan)

	_, err = io.ReadAll(conn)
	if err != nil {
		log.Printf("Error reading response: %v", err)
	}

	readSpan.End()

	_, closeSpan := tracer.Start(ctx, "close")

	sockSentParentSpan(connFd, closeSpan)

	conn.Close()

	closeSpan.End()

	connSpan.End()

	err = processor.ForceFlush(context.Background())
	if err != nil {
		log.Fatalf("Error flushing spans: %v", err)
	}
}
