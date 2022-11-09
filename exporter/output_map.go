package exporter

import (
	"fmt"
	"log"
	"time"

	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/config"
	"github.com/cloudflare/ebpf_exporter/decoder"
	"github.com/prometheus/client_golang/prometheus"
)

func newOutputMap(decoders *decoder.Set, module *libbpfgo.Module, counterConfig config.Counter) (prometheus.Collector, error) {
	m, err := module.GetMap(counterConfig.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve map %q: %v", counterConfig.Name, err)
	}

	switch m.Type() {
	case libbpfgo.MapTypePerfEventArray:
		return newPerfBufSink(decoders, module, counterConfig)
	case libbpfgo.MapTypeRingbuf:
		return newRingBufSink(decoders, module, counterConfig)
	default:
		return nil, nil
	}
}

func newPerfBufSink(decoders *decoder.Set, module *libbpfgo.Module, counterConfig config.Counter) (*outputMapSink, error) {
	receiveCh := make(chan []byte)

	perfBuf, err := module.InitPerfBuf(counterConfig.Name, receiveCh, nil, 1024)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize perf_buf: %v", err)
	}

	sink := newOutputMapSink(receiveCh, decoders, module, counterConfig)

	perfBuf.Start()

	return sink, nil
}

func newRingBufSink(decoders *decoder.Set, module *libbpfgo.Module, counterConfig config.Counter) (*outputMapSink, error) {
	receiveCh := make(chan []byte)

	ringBuf, err := module.InitRingBuf(counterConfig.Name, receiveCh)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize ring_buf: %v", err)
	}

	sink := newOutputMapSink(receiveCh, decoders, module, counterConfig)

	ringBuf.Start()

	return sink, nil
}

type outputMapSink struct {
	*prometheus.CounterVec
	counterConfig config.Counter
	receiveCh     <-chan []byte
}

func newOutputMapSink(receiveCh <-chan []byte, decoders *decoder.Set, module *libbpfgo.Module, counterConfig config.Counter) *outputMapSink {
	sink := &outputMapSink{
		counterConfig: counterConfig,
		receiveCh:     receiveCh,
	}

	sink.resetCounterVec()

	go receiveSinkEvents(receiveCh, sink.CounterVec, decoders, sink.counterConfig.Labels)
	go resetSinkTimer(sink)

	return sink
}

func (s *outputMapSink) resetCounterVec() {
	s.CounterVec = createCounterVecForMap(s.counterConfig, labelNamesFromCounterConfig(s.counterConfig))
}

func createCounterVecForMap(counterConfig config.Counter, labelNames []string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      counterConfig.Name,
		Help:      counterConfig.Help,
	}, labelNames)
}

func labelNamesFromCounterConfig(counterConfig config.Counter) (labelNames []string) {
	for _, label := range counterConfig.Labels {
		labelNames = append(labelNames, label.Name)
	}

	return
}

func receiveSinkEvents(receive <-chan []byte, counter *prometheus.CounterVec, decoders *decoder.Set, labels []config.Label) {
	for rawBytes := range receive {
		// https://github.com/cilium/ebpf/pull/94#discussion_r425823371
		// https://lore.kernel.org/patchwork/patch/1244339/
		var validDataSize uint
		for _, labelConfig := range labels {
			validDataSize += labelConfig.Size
		}

		labelValues, err := decoders.DecodeLabels(rawBytes[:validDataSize], labels)
		if err != nil {
			if err != decoder.ErrSkipLabelSet {

				log.Printf("Failed to decode labels: %s", err)
			}

			continue

		}

		counter.WithLabelValues(labelValues...).Inc()
	}
}

func resetSinkTimer(sink *outputMapSink) {
	if sink.counterConfig.FlushInterval == 0 {
		return
	}

	ticker := time.NewTicker(sink.counterConfig.FlushInterval)

	for {
		<-ticker.C
		sink.resetCounterVec()
	}
}
