package exporter

import (
	"log"
	"time"

	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/config"
	"github.com/cloudflare/ebpf_exporter/decoder"
	"github.com/prometheus/client_golang/prometheus"
)

type RingBufSink struct {
	counterConfig config.Counter
	counterVec    *prometheus.CounterVec
}

func NewRingBufSink(decoders *decoder.Set, module *libbpfgo.Module, counterConfig config.Counter) *RingBufSink {
	var (
		receiveCh = make(chan []byte)
	)

	sink := &RingBufSink{
		counterConfig: counterConfig,
	}
	sink.resetCounterVec()

	ringBuf, err := module.InitRingBuf(counterConfig.Name, receiveCh)

	if err != nil {
		log.Fatalf("Can't init RingBuf: %s", err)
	}

	go func(sink *RingBufSink, receiveCh <-chan []byte) {
		for rawBytes := range receiveCh {
			var validDataSize uint
			for _, labelConfig := range sink.counterConfig.Labels {
				validDataSize += labelConfig.Size
			}

			labelValues, err := decoders.DecodeLabels(rawBytes[:validDataSize], sink.counterConfig.Labels)
			if err != nil {
				if err == decoder.ErrSkipLabelSet {
					continue
				}

				log.Printf("Failed to decode labels: %s", err)
			}

			sink.counterVec.WithLabelValues(labelValues...).Inc()

		}
	}(sink, receiveCh)

	go func(sink *RingBufSink) {
		flushDuration := time.Hour
		if sink.counterConfig.FlushInterval > 0 {
			flushDuration = sink.counterConfig.FlushInterval
		}

		ticker := time.NewTicker(flushDuration)

		for {
			<-ticker.C
			sink.resetCounterVec()
		}
	}(sink)

	ringBuf.Start()

	return sink
}

func (s *RingBufSink) Collect(ch chan<- prometheus.Metric) {
	s.counterVec.Collect(ch)
}

func (s *RingBufSink) Describe(ch chan<- *prometheus.Desc) {
	s.counterVec.Describe(ch)
}

func (s *RingBufSink) resetCounterVec() {
	s.counterVec = createCounterVecForMap(s.counterConfig, labelNamesFromCounterConfig(s.counterConfig))
}
