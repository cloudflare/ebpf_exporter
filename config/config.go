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
	Name       string      `yaml:"name"`
	Metrics    Metrics     `yaml:"metrics"`
	PerfEvents []PerfEvent `yaml:"perf_events"`
	Kaddrs     []string    `yaml:"kaddrs"`
}

// PerfEvent describes perf_event to attach to
type PerfEvent struct {
	Type            uint64 `yaml:"type"`
	Name            uint64 `yaml:"name"`
	Target          string `yaml:"target"`
	SamplePeriod    uint64 `yaml:"sample_period"`
	SampleFrequency uint64 `yaml:"sample_frequency"`
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
	Map                  string        `yaml:"map"`
	PerfMap              string        `yaml:"perf_map"`
	PerfMapFlushDuration time.Duration `yaml:"perf_map_flush_duration"`
	Labels               []Label       `yaml:"labels"`
}

// Histogram is a metric defining prometheus histogram
type Histogram struct {
	Name             string              `yaml:"name"`
	Help             string              `yaml:"help"`
	Map              string              `yaml:"map"`
	BucketType       HistogramBucketType `yaml:"bucket_type"`
	BucketMultiplier float64             `yaml:"bucket_multiplier"`
	BucketMin        int                 `yaml:"bucket_min"`
	BucketMax        int                 `yaml:"bucket_max"`
	BucketKeys       []float64           `yaml:"bucket_keys"`
	Labels           []Label             `yaml:"labels"`
}

// Label defines how to decode an element from eBPF map key
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
		for _, counter := range program.Metrics.Counters {
			if counter.Map == "" && counter.PerfMap == "" {
				return fmt.Errorf("counter %q in program %q lacks map definition", counter.Name, program.Name)
			}
		}

		for _, histogram := range program.Metrics.Histograms {
			if histogram.Map == "" {
				return fmt.Errorf("histogram %q in program %q lacks map definition", histogram.Name, program.Name)
			}
		}
	}

	return nil
}
