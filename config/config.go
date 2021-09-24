package config

import (
	"errors"
	"fmt"
	"time"
)

// Config defines exporter configuration
type Config struct {
	Programs []Program `yaml:"programs"`
}

// Program is an eBPF program with optional metrics attached to it
type Program struct {
	Name           string            `yaml:"name"`
	Metrics        Metrics           `yaml:"metrics"`
	Kprobes        map[string]string `yaml:"kprobes"`
	Kretprobes     map[string]string `yaml:"kretprobes"`
	Tracepoints    map[string]string `yaml:"tracepoints"`
	RawTracepoints map[string]string `yaml:"raw_tracepoints"`
	PerfEvents     []PerfEvent       `yaml:"perf_events"`
	Code           string            `yaml:"code"`
	Cflags         []string          `yaml:"cflags"`
	Kaddrs         []string          `yaml:"kaddrs"`
}

// PerfEvent describes perf_event to attach to
type PerfEvent struct {
	Type            int    `yaml:"type"`
	Name            int    `yaml:"name"`
	Target          string `yaml:"target"`
	SamplePeriod    int    `yaml:"sample_period"`
	SampleFrequency int    `yaml:"sample_frequency"`
}

// Metrics is a collection of metrics attached to a program
type Metrics struct {
	Counters   []Counter   `yaml:"counters"`
	Histograms []Histogram `yaml:"histograms"`
}

// Counter is a metric defining prometheus counter
type Counter struct {
	Name                 string        `yaml:"name"`
	Help                 string        `yaml:"help"`
	Table                string        `yaml:"table"`
	PerfMap              string        `yaml:"perf_map"`
	PerfMapFlushDuration time.Duration `yaml:"perf_map_flush_duration"`
	Labels               []Label       `yaml:"labels"`
}

// Histogram is a metric defining prometheus histogram
type Histogram struct {
	Name             string              `yaml:"name"`
	Help             string              `yaml:"help"`
	Table            string              `yaml:"table"`
	BucketType       HistogramBucketType `yaml:"bucket_type"`
	BucketMultiplier float64             `yaml:"bucket_multiplier"`
	BucketMin        int                 `yaml:"bucket_min"`
	BucketMax        int                 `yaml:"bucket_max"`
	BucketKeys       []float64           `yaml:"bucket_keys"`
	Labels           []Label             `yaml:"labels"`
}

// Label defines how to decode an element from eBPF table key
// with the list of decoders
type Label struct {
	Name     string    `yaml:"name"`
	Size     uint      `yaml:"size"`
	Decoders []Decoder `yaml:"decoders"`
}

// Decoder defines how to decode value
type Decoder struct {
	Name         string            `yaml:"name"`
	StaticMap    map[string]string `yaml:"static_map"`
	Regexps      []string          `yaml:"regexps"`
	AllowUnknown bool              `yaml:"allow_unknown"`
}

// HistogramBucketType is an enum to define how to interpret histogram
type HistogramBucketType string

const (
	// HistogramBucketExp2 means histograms with power-of-two keys
	HistogramBucketExp2 = "exp2"
	// HistogramBucketLinear means histogram with linear keys
	HistogramBucketLinear = "linear"
	// HistogramBucketFixed means histogram with fixed user-defined keys
	HistogramBucketFixed = "fixed"
)

func ValidateConfig(c *Config) error {
	if len(c.Programs) == 0 {
		return errors.New("no programs specified")
	}

	for _, program := range c.Programs {
		if program.Code == "" {
			return fmt.Errorf("program (%s) has no code section", program.Name)
		}
		if len(program.Kprobes)+len(program.Kretprobes)+len(program.Tracepoints)+len(program.RawTracepoints)+len(program.PerfEvents) == 0 {
			return fmt.Errorf("program (%s) has no probes, tracepoints, or perf events", program.Name)
		}
	}

	return nil
}
