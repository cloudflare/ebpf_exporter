package exporter

import (
	"log"
	"time"

	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/v2/config"
	"github.com/cloudflare/ebpf_exporter/v2/decoder"
	"github.com/prometheus/client_golang/prometheus"
)

type perfEventArraySink struct {
	counterConfig config.Counter
	counterVec    *prometheus.CounterVec
	dropCounter   prometheus.Counter
}

func newPerfEventArraySink(decoders *decoder.Set, module *libbpfgo.Module, counterConfig config.Counter) *perfEventArraySink {
	var (
		receiveCh = make(chan []byte)
		lostCh    = make(chan uint64)
	)

	sink := &perfEventArraySink{
		counterConfig: counterConfig,
		dropCounter:   createDropCounterForPerfMap(counterConfig),
	}
	sink.resetCounterVec()

	perfEventBuf, err := module.InitPerfBuf(counterConfig.Name, receiveCh, lostCh, 1024)

	if err != nil {
		log.Fatalf("Can't init PerfBuf: %s", err)
	}

	go func(sink *perfEventArraySink, receiveCh <-chan []byte) {
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

	go func(sink *perfEventArraySink, lostCh <-chan uint64) {
		for droppedEvents := range lostCh {
			sink.dropCounter.Add(float64(droppedEvents))
		}
	}(sink, lostCh)

	go func(sink *perfEventArraySink) {
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

	perfEventBuf.Poll(300)

	return sink
}

func (s *perfEventArraySink) Collect(ch chan<- prometheus.Metric) {
	s.counterVec.Collect(ch)
}

func (s *perfEventArraySink) Describe(ch chan<- *prometheus.Desc) {
	s.counterVec.Describe(ch)
}

func (s *perfEventArraySink) resetCounterVec() {
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
		Namespace: "dropped_perf_event_map_events",
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
