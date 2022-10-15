package exporter

import (
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"unsafe"

	"github.com/cloudflare/ebpf_exporter/config"
	"github.com/cloudflare/ebpf_exporter/decoder"
	"github.com/cloudflare/ebpf_exporter/util"
	"github.com/prometheus/client_golang/prometheus"

	bpf "github.com/aquasecurity/libbpfgo"
)

// Namespace to use for all metrics
const prometheusNamespace = "ebpf_exporter"

// Exporter is a ebpf_exporter instance implementing prometheus.Collector
type Exporter struct {
	config              config.Config
	modules             map[string]*bpf.Module
	perfMapCollectors   []*PerfMapSink
	kaddrs              map[string]uint64
	enabledProgramsDesc *prometheus.Desc
	programInfoDesc     *prometheus.Desc
	programTags         map[string]map[string]string
	descs               map[string]map[string]*prometheus.Desc
	decoders            *decoder.Set
}

// New creates a new exporter with the provided config
func New(cfg config.Config) (*Exporter, error) {
	err := config.ValidateConfig(&cfg)
	if err != nil {
		return nil, fmt.Errorf("error validating config: %s", err)
	}

	enabledProgramsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "enabled_programs"),
		"The set of enabled programs",
		[]string{"name"},
		nil,
	)

	programInfoDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "ebpf_programs"),
		"Info about ebpf programs",
		[]string{"program", "function", "tag"},
		nil,
	)

	return &Exporter{
		config:              cfg,
		modules:             map[string]*bpf.Module{},
		kaddrs:              map[string]uint64{},
		enabledProgramsDesc: enabledProgramsDesc,
		programInfoDesc:     programInfoDesc,
		programTags:         map[string]map[string]string{},
		descs:               map[string]map[string]*prometheus.Desc{},
		decoders:            decoder.NewSet(),
	}, nil
}

// Attach injects eBPF into kernel and attaches necessary kprobes
func (e *Exporter) Attach(configPath string) error {
	for _, program := range e.config.Programs {
		if _, ok := e.modules[program.Name]; ok {
			return fmt.Errorf("multiple programs with name %q", program.Name)
		}

		bpfProgPath := filepath.Join(configPath, fmt.Sprintf("%s.bpf.o", program.Name))
		bpfModule, err := bpf.NewModuleFromFile(bpfProgPath)
		if err != nil {
			return fmt.Errorf("error creating module from %q: %v", bpfProgPath, err)
		}

		err = bpfModule.BPFLoadObject()
		if err != nil {
			return fmt.Errorf("error loading bpf object from %q: %v", bpfProgPath, err)
		}

		tags, err := attach(bpfModule, program.Kprobes, program.Kretprobes, program.Tracepoints, program.RawTracepoints)
		if err != nil {
			return fmt.Errorf("failed to attach to program %q: %s", program.Name, err)
		}

		e.programTags[program.Name] = tags
		for _, perfEventConfig := range program.PerfEvents {
			target, err := bpfModule.GetProgram(perfEventConfig.Target)
			if err != nil {
				return fmt.Errorf("failed to load target %q in program %q: %s", perfEventConfig.Target, program.Name, err)
			}

			_, err = target.AttachPerfEvent(target.FileDescriptor())
			if err != nil {
				return fmt.Errorf("failed to attach perf event %d:%d to %q in program %q: %s", perfEventConfig.Type, perfEventConfig.Name, perfEventConfig.Target, program.Name, err)
			}
		}
		e.modules[program.Name] = bpfModule
	}

	return nil
}

// Describe satisfies prometheus.Collector interface by sending descriptions
// for all metrics the exporter can possibly report
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	addDescs := func(programName string, name string, help string, labels []config.Label) {
		if _, ok := e.descs[programName][name]; !ok {
			labelNames := []string{}

			for _, label := range labels {
				labelNames = append(labelNames, label.Name)
			}

			e.descs[programName][name] = prometheus.NewDesc(prometheus.BuildFQName(prometheusNamespace, "", name), help, labelNames, nil)
		}

		ch <- e.descs[programName][name]
	}

	ch <- e.enabledProgramsDesc
	ch <- e.programInfoDesc

	for _, program := range e.config.Programs {
		if _, ok := e.descs[program.Name]; !ok {
			e.descs[program.Name] = map[string]*prometheus.Desc{}
		}

		for _, counter := range program.Metrics.Counters {
			if len(counter.PerfMap) != 0 {
				perfSink := NewPerfMapSink(e.decoders, e.modules[program.Name], counter)
				e.perfMapCollectors = append(e.perfMapCollectors, perfSink)
			}

			addDescs(program.Name, counter.Name, counter.Help, counter.Labels)
		}

		for _, histogram := range program.Metrics.Histograms {
			addDescs(program.Name, histogram.Name, histogram.Help, histogram.Labels[0:len(histogram.Labels)-1])
		}
	}
}

// Collect satisfies prometheus.Collector interface and sends all metrics
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	for _, program := range e.config.Programs {
		ch <- prometheus.MustNewConstMetric(e.enabledProgramsDesc, prometheus.GaugeValue, 1, program.Name)
	}

	for program, tags := range e.programTags {
		for function, tag := range tags {
			ch <- prometheus.MustNewConstMetric(e.programInfoDesc, prometheus.GaugeValue, 1, program, function, fmt.Sprintf("%s", tag))
		}
	}

	for _, perfMapCollector := range e.perfMapCollectors {
		perfMapCollector.Collect(ch)
	}

	e.collectCounters(ch)
	e.collectHistograms(ch)
}

// collectCounters sends all known counters to prometheus
func (e *Exporter) collectCounters(ch chan<- prometheus.Metric) {
	for _, program := range e.config.Programs {
		for _, counter := range program.Metrics.Counters {
			if len(counter.PerfMap) != 0 {
				continue
			}

			tableValues, err := e.tableValues(e.modules[program.Name], counter.Table, counter.Labels)
			if err != nil {
				log.Printf("Error getting table %q values for metric %q of program %q: %s", counter.Table, counter.Name, program.Name, err)
				continue
			}

			desc := e.descs[program.Name][counter.Name]

			for _, metricValue := range tableValues {
				ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, metricValue.value, metricValue.labels...)
			}
		}
	}
}

// collectHistograms sends all known historams to prometheus
func (e *Exporter) collectHistograms(ch chan<- prometheus.Metric) {
	for _, program := range e.config.Programs {
		for _, histogram := range program.Metrics.Histograms {
			skip := false

			histograms := map[string]histogramWithLabels{}

			tableValues, err := e.tableValues(e.modules[program.Name], histogram.Table, histogram.Labels)
			if err != nil {
				log.Printf("Error getting table %q values for metric %q of program %q: %s", histogram.Table, histogram.Name, program.Name, err)
				continue
			}

			// Taking the last label and using int as bucket delimiter, for example:
			//
			// Before:
			// * [sda, read, 1ms] -> 10
			// * [sda, read, 2ms] -> 2
			// * [sda, read, 4ms] -> 5
			//
			// After:
			// * [sda, read] -> {1ms -> 10, 2ms -> 2, 4ms -> 5}
			for _, metricValue := range tableValues {
				labels := metricValue.labels[0 : len(metricValue.labels)-1]

				key := fmt.Sprintf("%#v", labels)

				if _, ok := histograms[key]; !ok {
					histograms[key] = histogramWithLabels{
						labels:  labels,
						buckets: map[float64]uint64{},
					}
				}

				leUint, err := strconv.ParseUint(metricValue.labels[len(metricValue.labels)-1], 0, 64)
				if err != nil {
					log.Printf("Error parsing float value for bucket %#v in table %q of program %q: %s", metricValue.labels, histogram.Table, program.Name, err)
					skip = true
					break
				}

				histograms[key].buckets[float64(leUint)] = uint64(metricValue.value)
			}

			if skip {
				continue
			}

			desc := e.descs[program.Name][histogram.Name]

			for _, histogramSet := range histograms {
				buckets, count, sum, err := transformHistogram(histogramSet.buckets, histogram)
				if err != nil {
					log.Printf("Error transforming histogram for metric %q in program %q: %s", histogram.Name, program.Name, err)
					continue
				}

				// Sum is explicitly set to zero. We only take bucket values from
				// eBPF tables, which means we lose precision and cannot calculate
				// average values from histograms anyway.
				// Lack of sum also means we cannot have +Inf bucket, only some finite
				// value bucket, eBPF programs must cap bucket values to work with this.
				ch <- prometheus.MustNewConstHistogram(desc, count, sum, buckets, histogramSet.labels...)
			}
		}
	}
}

// tableValues returns values in the requested table to be used in metircs
func (e *Exporter) tableValues(module *bpf.Module, tableName string, labels []config.Label) ([]metricValue, error) {
	values := []metricValue{}

	table, err := module.GetMap(tableName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve table %q: %v", tableName, err)
	}

	keySize := uint(0)
	for _, label := range labels {
		keySize += label.Size
	}

	iter := table.Iterator()

	for iter.Next() {
		key := iter.Key()
		raw := *(*string)(unsafe.Pointer(&key))

		mv := metricValue{
			raw:    raw,
			labels: make([]string, len(labels)),
		}

		mv.labels, err = e.decoders.DecodeLabels(key, labels)
		if err != nil {
			if err == decoder.ErrSkipLabelSet {
				continue
			}

			return nil, err
		}

		// Assuming counter's value type is always u64
		v, err := table.GetValue(unsafe.Pointer(&key[0]))
		if err != nil {
			return nil, err
		}

		mv.value = float64(util.GetHostByteOrder().Uint64(v))

		values = append(values, mv)
	}

	return values, nil
}

func (e Exporter) exportTables() (map[string]map[string][]metricValue, error) {
	tables := map[string]map[string][]metricValue{}

	for _, program := range e.config.Programs {
		module := e.modules[program.Name]
		if module == nil {
			return nil, fmt.Errorf("module for program %q is not attached", program.Name)
		}

		if _, ok := tables[program.Name]; !ok {
			tables[program.Name] = map[string][]metricValue{}
		}

		metricTables := map[string][]config.Label{}

		for _, counter := range program.Metrics.Counters {
			if counter.Table != "" {
				metricTables[counter.Table] = counter.Labels
			}
		}

		for _, histogram := range program.Metrics.Histograms {
			if histogram.Table != "" {
				metricTables[histogram.Table] = histogram.Labels
			}
		}

		for name, labels := range metricTables {
			metricValues, err := e.tableValues(e.modules[program.Name], name, labels)
			if err != nil {
				return nil, fmt.Errorf("error getting values for table %q of program %q: %s", name, program.Name, err)
			}

			tables[program.Name][name] = metricValues
		}
	}

	return tables, nil
}

// TablesHandler is a debug handler to print raw values of kernel maps
func (e *Exporter) TablesHandler(w http.ResponseWriter, r *http.Request) {
	tables, err := e.exportTables()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Add("Content-type", "text/plain")
		if _, err = fmt.Fprintf(w, "%s\n", err); err != nil {
			log.Printf("Error returning error to client %q: %s", r.RemoteAddr, err)
			return
		}
		return
	}

	w.Header().Add("Content-type", "text/plain")

	buf := []byte{}

	for program, tables := range tables {
		buf = append(buf, fmt.Sprintf("## Program: %s\n\n", program)...)

		for name, table := range tables {
			buf = append(buf, fmt.Sprintf("### Table: %s\n\n", name)...)

			buf = append(buf, "```\n"...)
			for _, row := range table {
				buf = append(buf, fmt.Sprintf("%s (%v) -> %f\n", row.raw, row.labels, row.value)...)
			}
			buf = append(buf, "```\n\n"...)
		}
	}

	if _, err = w.Write(buf); err != nil {
		log.Printf("Error returning table contents to client %q: %s", r.RemoteAddr, err)
	}
}

// metricValue is a row in a kernel map
type metricValue struct {
	// raw is a raw key value provided by kernel
	raw string
	// labels are decoded from the raw key
	labels []string
	// value is the kernel map value
	value float64
}
