package exporter

import (
	"log"
	"time"

	"github.com/cloudflare/ebpf_exporter/config"
	"github.com/cloudflare/ebpf_exporter/decoder"
	"github.com/iovisor/gobpf/bcc"
	"github.com/prometheus/client_golang/prometheus"
)

type PerfMapSink struct {
	counterConfig config.Counter
	counterVec    *prometheus.CounterVec
}

func NewPerfMapSink(decoders *decoder.Set, module *bcc.Module, counterConfig config.Counter) *PerfMapSink {
	var (
		receiveCh = make(chan []byte)
		lostCh    = make(chan uint64)
	)

	sink := &PerfMapSink{
		counterConfig: counterConfig,
	}
	sink.resetCounterVec()

	table := bcc.NewTable(module.TableId(counterConfig.PerfMap), module)

	perfMap, err := bcc.InitPerfMap(table, receiveCh, lostCh)
	if err != nil {
		log.Panicf("Can't init PerfMap: %s", err)
	}

	go func(sink *PerfMapSink, counterConfig config.Counter, receiveCh <-chan []byte) {
		for rawBytes := range receiveCh {
			// https://github.com/cilium/ebpf/pull/94#discussion_r425823371
			// https://lore.kernel.org/patchwork/patch/1244339/
			var validDataSize uint
			for _, labelConfig := range counterConfig.Labels {
				validDataSize += labelConfig.Size
			}

			labelValues, err := decoders.DecodeLabels(rawBytes[:validDataSize], counterConfig.Labels)
			if err != nil {
				if err == decoder.ErrSkipLabelSet {
					continue
				}

				log.Printf("failed to decode labels: %s", err)
			}

			sink.counterVec.WithLabelValues(labelValues...).Inc()

		}
	}(sink, counterConfig, receiveCh)

	go func(sink *PerfMapSink) {
		ticker := time.NewTicker(time.Hour)

		for {
			<-ticker.C
			sink.resetCounterVec()
		}
	}(sink)

	perfMap.Start()

	return sink
}

func (s *PerfMapSink) resetCounterVec() {
	s.counterVec = createCounterVecForPerfMap(s.counterConfig, labelNamesFromCounterConfig(s.counterConfig))
}

func (s *PerfMapSink) Collect(ch chan<- prometheus.Metric) {
	s.counterVec.Collect(ch)
}

func (s *PerfMapSink) Describe(ch chan<- *prometheus.Desc) {
	s.counterVec.Describe(ch)
}

func createCounterVecForPerfMap(counterConfig config.Counter, labelNames []string) *prometheus.CounterVec {
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
