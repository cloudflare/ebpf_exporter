package exporter

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/v2/cgroup"
	"github.com/cloudflare/ebpf_exporter/v2/config"
	"github.com/cloudflare/ebpf_exporter/v2/decoder"
	"github.com/cloudflare/ebpf_exporter/v2/tracing"
	"github.com/cloudflare/ebpf_exporter/v2/util"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Namespace to use for all metrics
const prometheusNamespace = "ebpf_exporter"

var percpuMapTypes = map[libbpfgo.MapType]struct{}{
	libbpfgo.MapTypePerCPUHash:    {},
	libbpfgo.MapTypePerCPUArray:   {},
	libbpfgo.MapTypeLRUPerCPUHash: {},
}

// Exporter is a ebpf_exporter instance implementing prometheus.Collector
type Exporter struct {
	configs []config.Config
	modules map[string]*libbpfgo.Module

	perfEventArrayCollectors []*perfEventArraySink
	kaddrs                   map[string]uint64
	enabledConfigsDesc       *prometheus.Desc
	programInfoDesc          *prometheus.Desc
	programAttachedDesc      *prometheus.Desc
	programRunTimeDesc       *prometheus.Desc
	programRunCountDesc      *prometheus.Desc
	decoderErrorCount        *prometheus.CounterVec
	attachedProgs            map[string]map[*libbpfgo.BPFProg]*libbpfgo.BPFLink
	descs                    map[string]map[string]*prometheus.Desc
	decoders                 *decoder.Set
	btfPath                  string
	tracingProvider          tracing.Provider
	active                   bool
	activeMutex              sync.Mutex
	cgroupMonitor            *cgroup.Monitor
}

// New creates a new exporter with the provided config
func New(configs []config.Config, tracingProvider tracing.Provider, btfPath string) (*Exporter, error) {
	enabledConfigsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "enabled_configs"),
		"The set of enabled configs",
		[]string{"name"},
		nil,
	)

	programInfoDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "ebpf_program_info"),
		"Info about ebpf programs",
		[]string{"config", "program", "tag", "id"},
		nil,
	)

	programAttachedDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "ebpf_program_attached"),
		"Whether a program is attached",
		[]string{"id"},
		nil,
	)

	programRunTimeDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "ebpf_program_run_time_seconds"),
		"How long has the program been executing",
		[]string{"id"},
		nil,
	)

	programRunCountDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "ebpf_program_run_count_total"),
		"How many times has the program been executed",
		[]string{"id"},
		nil,
	)

	decoderErrorCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{Namespace: prometheusNamespace, Name: "decoder_errors_total", Help: "How many times has decoders encountered errors"},
		[]string{"config"},
	)

	for _, config := range configs {
		decoderErrorCount.WithLabelValues(config.Name).Add(0.0)
	}

	monitor, err := cgroup.NewMonitor("/sys/fs/cgroup")
	if err != nil {
		return nil, fmt.Errorf("error creating cgroup monitor: %w", err)
	}

	decoders, err := decoder.NewSet(monitor)
	if err != nil {
		return nil, fmt.Errorf("error creating decoder set: %w", err)
	}

	return &Exporter{
		configs:             configs,
		modules:             map[string]*libbpfgo.Module{},
		kaddrs:              map[string]uint64{},
		enabledConfigsDesc:  enabledConfigsDesc,
		programInfoDesc:     programInfoDesc,
		programAttachedDesc: programAttachedDesc,
		programRunTimeDesc:  programRunTimeDesc,
		programRunCountDesc: programRunCountDesc,
		decoderErrorCount:   decoderErrorCount,
		attachedProgs:       map[string]map[*libbpfgo.BPFProg]*libbpfgo.BPFLink{},
		descs:               map[string]map[string]*prometheus.Desc{},
		decoders:            decoders,
		btfPath:             btfPath,
		tracingProvider:     tracingProvider,
		cgroupMonitor:       monitor,
	}, nil
}

// Attach injects eBPF into kernel and attaches necessary programs
func (e *Exporter) Attach() error {
	tracer := e.tracingProvider.Tracer("")

	ctx, attachSpan := tracer.Start(context.Background(), "attach")
	defer attachSpan.End()

	_, registerHandlersSpan := tracer.Start(ctx, "register_handlers")
	defer registerHandlersSpan.End()

	err := registerHandlers()
	if err != nil {
		return fmt.Errorf("error registering libbpf handlers: %w", err)
	}

	err = registerXDPHandler()
	if err != nil {
		return fmt.Errorf("error registering xdp handlers: %w", err)
	}

	registerHandlersSpan.End()

	ctx, attachConfigsSpan := tracer.Start(ctx, "attach_configs")
	defer attachConfigsSpan.End()

	for _, cfg := range e.configs {
		ctx, attachConfigSpan := tracer.Start(ctx, "attach_config", trace.WithAttributes(attribute.String("config", cfg.Name)))

		err = e.attachConfig(ctx, cfg)
		if err != nil {
			attachConfigSpan.SetStatus(codes.Error, err.Error())
			attachConfigSpan.End()
			return err
		}

		attachConfigSpan.End()
	}

	attachConfigsSpan.End()

	postAttachMark()

	e.active = true

	return nil
}

func (e *Exporter) attachConfig(ctx context.Context, cfg config.Config) error {
	tracer := e.tracingProvider.Tracer("")

	if _, ok := e.modules[cfg.Name]; ok {
		return fmt.Errorf("multiple configs with name %q", cfg.Name)
	}

	_, newModuleSpan := tracer.Start(ctx, "new_module")
	defer newModuleSpan.End()

	args := libbpfgo.NewModuleArgs{
		BPFObjPath:      cfg.BPFPath,
		SkipMemlockBump: true, // Let libbpf itself decide whether it is needed
	}

	if e.btfPath != "" {
		if _, err := os.Stat(e.btfPath); err == nil {
			args.BTFObjPath = e.btfPath
		} else if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("could not find BTF file %q", e.btfPath)
		} else {
			return fmt.Errorf("failed to retrieve file info for %q: %w", e.btfPath, err)
		}
	}

	module, err := libbpfgo.NewModuleFromFileArgs(args)
	if err != nil {
		return fmt.Errorf("error creating module from %q for config %q: %w", cfg.BPFPath, cfg.Name, err)
	}

	newModuleSpan.End()

	if len(cfg.Kaddrs) > 0 {
		err = e.passKaddrs(ctx, module, cfg)
		if err != nil {
			return fmt.Errorf("error passing kaddrs to config %q: %w", cfg.Name, err)
		}
	}

	_, bpfLoadObjectSpan := tracer.Start(ctx, "bpf_load_object")
	defer bpfLoadObjectSpan.End()

	err = module.BPFLoadObject()
	if err != nil {
		return fmt.Errorf("error loading bpf object from %q for config %q: %w", cfg.BPFPath, cfg.Name, err)
	}

	bpfLoadObjectSpan.End()

	_, attachModuleSpan := tracer.Start(ctx, "attach_module")

	attachments := attachModule(attachModuleSpan, module, cfg)

	attachModuleSpan.End()

	err = validateMaps(module, cfg)
	if err != nil {
		return fmt.Errorf("error validating maps for config %q: %w", cfg.Name, err)
	}

	// attach cgroup id map if exists
	if len(cfg.CgroupIdMap.Name) > 0 {
		if err := e.attachCgroupIdMap(module, cfg); err != nil {
			return err
		}
	}

	e.attachedProgs[cfg.Name] = attachments
	e.modules[cfg.Name] = module

	return nil
}

func (e *Exporter) attachCgroupIdMap(module *libbpfgo.Module, cfg config.Config) error {
	cgMap, err := newCgroupIdMap(module, cfg)
	if err != nil {
		return err
	}
	if err := cgMap.subscribe(e.cgroupMonitor); err != nil {
		return err
	}
	go cgMap.runLoop()
	return nil
}

// Detach detaches bpf programs and maps for exiting
func (e *Exporter) Detach() {
	e.activeMutex.Lock()
	defer e.activeMutex.Unlock()

	e.active = false

	tracer := e.tracingProvider.Tracer("")

	ctx, attachSpan := tracer.Start(context.Background(), "detach")
	defer attachSpan.End()

	for name, module := range e.modules {
		_, moduleCloseSpan := tracer.Start(ctx, "close_module", trace.WithAttributes(attribute.String("config", name)))

		for prog, link := range e.attachedProgs[name] {
			if link == nil {
				continue
			}

			moduleCloseSpan.AddEvent("prog_detach", trace.WithAttributes(attribute.String("SEC", prog.SectionName())))

			if err := link.Destroy(); err != nil {
				log.Printf("Failed to detach program %q for config %q: %v", prog.Name(), name, err)
				moduleCloseSpan.RecordError(err)
				moduleCloseSpan.SetStatus(codes.Error, err.Error())
			}
		}

		moduleCloseSpan.AddEvent("close")

		module.Close()

		moduleCloseSpan.End()
	}
}

// MissedAttachments returns the list of module:prog names that failed to attach
func (e *Exporter) MissedAttachments() []string {
	missed := []string{}

	for name, progs := range e.attachedProgs {
		for prog, link := range progs {
			if link != nil {
				continue
			}

			missed = append(missed, fmt.Sprintf("%s:%s", name, prog.Name()))
		}
	}

	return missed
}

func (e *Exporter) passKaddrs(ctx context.Context, module *libbpfgo.Module, cfg config.Config) error {
	tracer := e.tracingProvider.Tracer("")

	passKaddrsCtx, passKaddrsSpan := tracer.Start(ctx, "pass_kaddrs")
	defer passKaddrsSpan.End()

	if len(e.kaddrs) == 0 {
		_, populateKaddrsSpan := tracer.Start(passKaddrsCtx, "populate_kaddrs")

		if err := e.populateKaddrs(); err != nil {
			err = fmt.Errorf("error populating kaddrs: %w", err)
			populateKaddrsSpan.SetStatus(codes.Error, err.Error())
			populateKaddrsSpan.End()
			return err
		}

		populateKaddrsSpan.End()
	}

	for _, kaddr := range cfg.Kaddrs {
		passKaddrsSpan.AddEvent("kaddr", trace.WithAttributes(attribute.String("symbol", kaddr)))

		addr, ok := e.kaddrs[kaddr]
		if !ok {
			err := fmt.Errorf("error finding kaddr for %q", kaddr)
			passKaddrsSpan.SetStatus(codes.Error, err.Error())
			return err
		}

		name := "kaddr_" + kaddr
		if err := module.InitGlobalVariable(name, addr); err != nil {
			err = fmt.Errorf("error setting kaddr value for %q (const volatile %q) to 0x%x: %w", kaddr, name, addr, err)
			passKaddrsSpan.SetStatus(codes.Error, err.Error())
			return err
		}
	}

	return nil
}

// populateKaddrs populates cache of ksym -> kaddr mappings
func (e *Exporter) populateKaddrs() error {
	fd, err := os.Open("/proc/kallsyms")
	if err != nil {
		return err
	}

	defer fd.Close()

	s := bufio.NewScanner(fd)
	for s.Scan() {
		parts := strings.Split(s.Text(), " ")
		if len(parts) != 3 {
			continue
		}

		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			return fmt.Errorf("error parsing addr %q from line %q: %w", parts[0], s.Text(), err)
		}

		e.kaddrs[parts[2]] = addr
	}

	return s.Err()
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

	ch <- e.enabledConfigsDesc
	ch <- e.programInfoDesc
	ch <- e.programAttachedDesc

	e.decoderErrorCount.Describe(ch)

	for _, cfg := range e.configs {
		if _, ok := e.descs[cfg.Name]; !ok {
			e.descs[cfg.Name] = map[string]*prometheus.Desc{}
		}

		for _, counter := range cfg.Metrics.Counters {
			if counter.PerfEventArray {
				perfSink := newPerfEventArraySink(e.decoders, e.modules[cfg.Name], counter, e.decoderErrorCount.WithLabelValues(cfg.Name))
				e.perfEventArrayCollectors = append(e.perfEventArrayCollectors, perfSink)
			}

			addDescs(cfg.Name, counter.Name, counter.Help, counter.Labels)
		}

		for _, histogram := range cfg.Metrics.Histograms {
			addDescs(cfg.Name, histogram.Name, histogram.Help, histogram.Labels[0:len(histogram.Labels)-1])
		}

		if e.tracingProvider == nil && len(cfg.Tracing.Spans) > 0 {
			log.Printf("Tracing is not enabled, but some spans are configured in config %q", cfg.Name)
		} else {
			for _, span := range cfg.Tracing.Spans {
				startTracingSink(e.tracingProvider, e.decoders, e.modules[cfg.Name], cfg.Name, span, e.decoderErrorCount.WithLabelValues(cfg.Name))
			}
		}
	}
}

// Collect satisfies prometheus.Collector interface and sends all metrics
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.activeMutex.Lock()
	defer e.activeMutex.Unlock()

	if !e.active {
		return
	}

	for _, cfg := range e.configs {
		ch <- prometheus.MustNewConstMetric(e.enabledConfigsDesc, prometheus.GaugeValue, 1, cfg.Name)
	}

	e.decoderErrorCount.Collect(ch)

	for name, attachments := range e.attachedProgs {
		for program, link := range attachments {
			info, err := extractProgramInfo(program)
			if err != nil {
				log.Printf("Error extracting program info for %q in config %q: %v", program.Name(), name, err)
			}

			id := strconv.Itoa(info.id)

			ch <- prometheus.MustNewConstMetric(e.programInfoDesc, prometheus.GaugeValue, 1, name, program.Name(), info.tag, id)

			attachedValue := 0.0
			if link != nil {
				attachedValue = 1.0
			}

			ch <- prometheus.MustNewConstMetric(e.programAttachedDesc, prometheus.GaugeValue, attachedValue, id)

			statsEnabled, err := bpfStatsEnabled()
			if err != nil {
				log.Printf("Error checking whether bpf stats are enabled: %v", err)
			} else if statsEnabled {
				ch <- prometheus.MustNewConstMetric(e.programRunTimeDesc, prometheus.CounterValue, info.runTime.Seconds(), id)
				ch <- prometheus.MustNewConstMetric(e.programRunCountDesc, prometheus.CounterValue, float64(info.runCount), id)
			}
		}
	}

	for _, perfEventArrayCollector := range e.perfEventArrayCollectors {
		perfEventArrayCollector.Collect(ch)
	}

	e.collectCounters(ch)
	e.collectHistograms(ch)
}

// collectCounters sends all known counters to prometheus
func (e *Exporter) collectCounters(ch chan<- prometheus.Metric) {
	for _, cfg := range e.configs {
		for _, counter := range cfg.Metrics.Counters {
			if counter.PerfEventArray {
				continue
			}

			mapValues, err := e.mapValues(e.modules[cfg.Name], counter.Name, counter.Labels)
			if err != nil {
				e.decoderErrorCount.WithLabelValues(cfg.Name).Inc()
				log.Printf("Error getting map %q values for metric %q of config %q: %v", counter.Name, counter.Name, cfg.Name, err)
				continue
			}

			aggregatedMapValues := aggregateMapValues(mapValues)

			desc := e.descs[cfg.Name][counter.Name]

			for _, metricValue := range aggregatedMapValues {
				ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, metricValue.value, metricValue.labels...)
			}
		}
	}
}

// collectHistograms sends all known histograms to prometheus
func (e *Exporter) collectHistograms(ch chan<- prometheus.Metric) {
	for _, cfg := range e.configs {
		for _, histogram := range cfg.Metrics.Histograms {
			skip := false

			histograms := map[string]histogramWithLabels{}

			mapValues, err := e.mapValues(e.modules[cfg.Name], histogram.Name, histogram.Labels)
			if err != nil {
				e.decoderErrorCount.WithLabelValues(cfg.Name).Inc()
				log.Printf("Error getting map %q values for metric %q of config %q: %v", histogram.Name, histogram.Name, cfg.Name, err)
				continue
			}

			aggregatedMapValues := aggregateMapValues(mapValues)

			// Taking the last label and using int as bucket delimiter, for example:
			//
			// Before:
			// * [sda, read, 1ms] -> 10
			// * [sda, read, 2ms] -> 2
			// * [sda, read, 4ms] -> 5
			//
			// After:
			// * [sda, read] -> {1ms -> 10, 2ms -> 2, 4ms -> 5}
			for _, metricValue := range aggregatedMapValues {
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
					log.Printf("Error parsing float value for bucket %#v in map %q of config %q: %v", metricValue.labels, histogram.Name, cfg.Name, err)
					skip = true
					break
				}

				histograms[key].buckets[float64(leUint)] = uint64(metricValue.value)
			}

			if skip {
				continue
			}

			desc := e.descs[cfg.Name][histogram.Name]

			for _, histogramSet := range histograms {
				buckets, count, sum, err := transformHistogram(histogramSet.buckets, histogram)
				if err != nil {
					log.Printf("Error transforming histogram for metric %q in config %q: %v", histogram.Name, cfg.Name, err)
					continue
				}

				ch <- prometheus.MustNewConstHistogram(desc, count, sum, buckets, histogramSet.labels...)
			}
		}
	}
}

// mapValues returns values in the requested map to be used in metrics
func (e *Exporter) mapValues(module *libbpfgo.Module, name string, labels []config.Label) ([]metricValue, error) {
	m, err := module.GetMap(name)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve map %q: %w", name, err)
	}

	metricValues, err := readMapValues(m, labels)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve map %q: %w", name, err)
	}

	_, percpu := percpuMapTypes[m.Type()]

	retainedMetricValues := []metricValue{}

	for i, mv := range metricValues {
		raw := mv.raw

		// If there are no labels, assume a single key of uint32(0)
		if len(labels) == 0 && bytes.Equal(mv.raw, []byte{0x0, 0x0, 0x0, 0x0}) {
			metricValues[i].labels = []string{}
			retainedMetricValues = append(retainedMetricValues, metricValues[i])
			continue
		}

		// If the metrics are percpu and cpu is the only label, ignore the first
		// uint32(0), same as above for the non-percpu case of no labels at all
		if percpu && len(labels) == 1 && labels[0].Name == "cpu" && bytes.Equal(mv.raw[:4], []byte{0x0, 0x0, 0x0, 0x0}) {
			raw = raw[4:]
		}

		metricValues[i].labels, err = e.decoders.DecodeLabelsForMetrics(raw, name, labels)
		if err != nil {
			if errors.Is(err, decoder.ErrSkipLabelSet) {
				continue
			}

			return nil, err
		}

		retainedMetricValues = append(retainedMetricValues, metricValues[i])
	}

	return retainedMetricValues, nil
}

func (e *Exporter) exportMaps() (map[string]map[string][]metricValue, error) {
	maps := map[string]map[string][]metricValue{}

	for _, cfg := range e.configs {
		module := e.modules[cfg.Name]
		if module == nil {
			return nil, fmt.Errorf("module for config %q is not attached", cfg.Name)
		}

		if _, ok := maps[cfg.Name]; !ok {
			maps[cfg.Name] = map[string][]metricValue{}
		}

		metricMaps := map[string][]config.Label{}

		for _, counter := range cfg.Metrics.Counters {
			if counter.Name != "" {
				metricMaps[counter.Name] = counter.Labels
			}
		}

		for _, histogram := range cfg.Metrics.Histograms {
			if histogram.Name != "" {
				metricMaps[histogram.Name] = histogram.Labels
			}
		}

		for name, labels := range metricMaps {
			metricValues, err := e.mapValues(e.modules[cfg.Name], name, labels)
			if err != nil {
				e.decoderErrorCount.WithLabelValues(cfg.Name).Inc()
				return nil, fmt.Errorf("error getting values for map %q of config %q: %w", name, cfg.Name, err)
			}

			maps[cfg.Name][name] = metricValues
		}
	}

	return maps, nil
}

// MapsHandler is a debug handler to print raw values of kernel maps
func (e *Exporter) MapsHandler(w http.ResponseWriter, r *http.Request) {
	maps, err := e.exportMaps()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Add("Content-Type", "text/plain")
		if _, err = fmt.Fprintf(w, "%s\n", err); err != nil {
			log.Printf("Error returning error to client %q: %v", r.RemoteAddr, err)
			return
		}
		return
	}

	w.Header().Add("Content-Type", "text/plain")

	buf := []byte{}

	for cfg, maps := range maps {
		buf = append(buf, fmt.Sprintf("## Config: %s\n\n", cfg)...)

		for name, m := range maps {
			buf = append(buf, fmt.Sprintf("### Map: %s\n\n", name)...)

			buf = append(buf, "```\n"...)
			for _, row := range m {
				buf = append(buf, fmt.Sprintf("%#v (labels: %v) -> %.0f\n", row.raw, row.labels, row.value)...)
			}
			buf = append(buf, "```\n\n"...)
		}
	}

	if _, err = w.Write(buf); err != nil {
		log.Printf("Error returning map contents to client %q: %v", r.RemoteAddr, err)
	}
}

func validateMaps(module *libbpfgo.Module, cfg config.Config) error {
	maps := []string{}

	for _, counter := range cfg.Metrics.Counters {
		if counter.Name != "" && !counter.PerfEventArray {
			maps = append(maps, counter.Name)
		}
	}

	for _, histogram := range cfg.Metrics.Histograms {
		if histogram.Name != "" {
			maps = append(maps, histogram.Name)
		}
	}

	for _, name := range maps {
		m, err := module.GetMap(name)
		if err != nil {
			return fmt.Errorf("failed to get map %q: %w", name, err)
		}

		valueSize := m.ValueSize()
		if valueSize != 8 {
			return fmt.Errorf("value size for map %q is not expected 8 bytes (u64), it is %d bytes", name, valueSize)
		}
	}

	return nil
}

// aggregateMapValues aggregates values so that the same set of labels is not repeated.
// This is useful for cases when underlying id maps to the same value for metrics.
// A concrete example is changing cgroup id mapping to the same cgroup name,
// as systemd recycles cgroup when the service is restarted. Without pre-aggregation
// here the metrics would break as prometheus does not allow the same set of labels
// to be repeated. This assumes that values are counters and should be summed.
func aggregateMapValues(values []metricValue) []aggregatedMetricValue {
	aggregated := []aggregatedMetricValue{}
	mapping := map[string]*aggregatedMetricValue{}

	for _, value := range values {
		key := strings.Join(value.labels, "|")

		if existing, ok := mapping[key]; !ok {
			mapping[key] = &aggregatedMetricValue{
				labels: value.labels,
				value:  value.value,
			}
		} else {
			existing.value += value.value
		}
	}

	for _, value := range mapping {
		aggregated = append(aggregated, *value)
	}

	return aggregated
}

func readMapValues(m *libbpfgo.BPFMap, labels []config.Label) ([]metricValue, error) {
	_, percpu := percpuMapTypes[m.Type()]

	// if the last label is cpu, split the counters per cpu
	addCPU := len(labels) > 0 && labels[len(labels)-1].Name == "cpu"

	metricValues := []metricValue{}

	iter := m.Iterator()

	for iter.Next() {
		key := iter.Key()

		if percpu {
			values, err := mapValuePerCPU(m, key)
			if err != nil {
				return nil, err
			}

			for cpu, value := range values {
				mv := metricValue{
					raw:   key,
					value: value,
				}

				if addCPU {
					// add CPU number as uint16 at the end
					cpuBytes := []byte{0x0, 0x0}
					util.GetHostByteOrder().PutUint16(cpuBytes, uint16(cpu))
					mv.raw = append(mv.raw, cpuBytes...)
				}

				metricValues = append(metricValues, mv)
			}
		} else {
			mv := metricValue{
				raw: key,
			}

			value, err := mapValue(m, key)
			if err != nil {
				return nil, err
			}

			mv.value = value

			metricValues = append(metricValues, mv)
		}
	}

	return metricValues, nil
}

func mapValue(m *libbpfgo.BPFMap, key []byte) (float64, error) {
	v, err := m.GetValue(unsafe.Pointer(&key[0]))
	if err != nil {
		return 0.0, err
	}

	return decodeValue(v), nil
}

func mapValuePerCPU(m *libbpfgo.BPFMap, key []byte) ([]float64, error) {
	values := []float64{}
	size := m.ValueSize()

	value, err := m.GetValue(unsafe.Pointer(&key[0]))
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(value); i += size {
		values = append(values, decodeValue(value[i:i+size]))
	}

	return values, err
}

// Assuming counter's value type is always u64
func decodeValue(value []byte) float64 {
	return float64(util.GetHostByteOrder().Uint64(value))
}

// metricValue is a row in a kernel map
type metricValue struct {
	// raw is a raw key value provided by kernel
	raw []byte
	// labels are decoded from the raw key
	labels []string
	// value is the kernel map value
	value float64
}

// aggregatedMetricValue is a value after aggregation of equal label sets
type aggregatedMetricValue struct {
	// labels are decoded from the raw key
	labels []string
	// value is the kernel map value
	value float64
}
