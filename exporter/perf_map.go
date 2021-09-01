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
	dropCounter   prometheus.Counter
}

func NewPerfMapSink(decoders *decoder.Set, module *bcc.Module, counterConfig config.Counter) *PerfMapSink {
	var (
		receiveCh = make(chan []byte)
		lostCh    = make(chan uint64)
	)

	sink := &PerfMapSink{
		counterConfig: counterConfig,
		dropCounter:   createDropCounterForPerfMap(counterConfig),
	}
	sink.resetCounterVec()

	table := bcc.NewTable(module.TableId(counterConfig.PerfMap), module)

	perfMap, err := bcc.InitPerfMap(table, receiveCh, lostCh)
	if err != nil {
		log.Fatalf("Can't init PerfMap: %s", err)
	}

	go func(sink *PerfMapSink, receiveCh <-chan []byte) {
		for rawBytes := range receiveCh {
			// https://github.com/cilium/ebpf/pull/94#discussion_r425823371
			// https://lore.kernel.org/patchwork/patch/1244339/
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

	go func(sink *PerfMapSink, lostCh <-chan uint64) {
		for droppedEvents := range lostCh {
			sink.dropCounter.Add(float64(droppedEvents))
		}
	}(sink, lostCh)

	go func(sink *PerfMapSink) {
		flushDuration := time.Hour
		if sink.counterConfig.PerfMapFlushDuration > 0 {
			flushDuration = sink.counterConfig.PerfMapFlushDuration
		}

		ticker := time.NewTicker(flushDuration)

		for {
			<-ticker.C
			sink.resetCounterVec()
		}
	}(sink)

	perfMap.Start()

	return sink
}

func (s *PerfMapSink) Collect(ch chan<- prometheus.Metric) {
	s.counterVec.Collect(ch)
}

func (s *PerfMapSink) Describe(ch chan<- *prometheus.Desc) {
	s.counterVec.Describe(ch)
}

func (s *PerfMapSink) resetCounterVec() {
	s.counterVec = createCounterVecForPerfMap(s.counterConfig, labelNamesFromCounterConfig(s.counterConfig))
}

func createCounterVecForPerfMap(counterConfig config.Counter, labelNames []string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      counterConfig.Name,
		Help:      counterConfig.Help,
	}, labelNames)
}

func createDropCounterForPerfMap(counterConfig config.Counter) prometheus.Counter {
	return prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "dropped_perf_map_events",
		Name:      counterConfig.Name,
		Help:      "Dropped perf map events",
	}, []string{}).WithLabelValues()
}

func labelNamesFromCounterConfig(counterConfig config.Counter) (labelNames []string) {
	for _, label := range counterConfig.Labels {
		labelNames = append(labelNames, label.Name)
	}

	return
}
