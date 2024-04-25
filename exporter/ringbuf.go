package exporter

import (
	"log"

	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/v2/config"
	"github.com/cloudflare/ebpf_exporter/v2/decoder"
	"github.com/cloudflare/ebpf_exporter/v2/tracing"
	"github.com/prometheus/client_golang/prometheus"
)

func startTracingSink(provider tracing.Provider, decoders *decoder.Set, module *libbpfgo.Module, config config.Span, errors prometheus.Counter) {
	input := make(chan []byte)

	ringBuf, err := module.InitRingBuf(config.RingBuf, input)
	if err != nil {
		log.Fatalf("Error initializing ringbuf %q: %v", config.RingBuf, err)
	}

	go tracing.HandleInput(input, provider, decoders, config, errors)

	ringBuf.Poll(325)
}
