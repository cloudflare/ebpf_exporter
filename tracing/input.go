package tracing

import (
	"errors"
	"log"

	"github.com/cloudflare/ebpf_exporter/v2/config"
	"github.com/cloudflare/ebpf_exporter/v2/decoder"
	"github.com/prometheus/client_golang/prometheus"
)

// HandleInput reads inputs from the input channel and turns them into spans
func HandleInput(input <-chan []byte, provider Provider, decoders *decoder.Set, configName string, config config.Span, errorCounter prometheus.Counter) {
	for raw := range input {
		err := handleRawBytes(raw, provider, decoders, configName, config)
		if err != nil {
			if !errors.Is(err, decoder.ErrSkipLabelSet) {
				errorCounter.Inc()
				log.Printf("Error handing raw span bytes: %v", err)
			}

			continue
		}
	}
}

func handleRawBytes(raw []byte, provider Provider, decoders *decoder.Set, configName string, config config.Span) error {
	decoded, err := extractLabels(raw, decoders, config)
	if err != nil {
		return err
	}

	return handleDecodedLabels(provider, decoded, configName, config)
}
