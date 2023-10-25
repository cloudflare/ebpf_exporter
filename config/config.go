package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v2"
)

// Config describes how to configure and extract metrics
type Config struct {
	Name    string   `yaml:"name"`
	Metrics Metrics  `yaml:"metrics"`
	Kaddrs  []string `yaml:"kaddrs"`
	BPFPath string
}

// Metrics is a collection of metrics attached to a program
type Metrics struct {
	Counters   []Counter   `yaml:"counters"`
	Histograms []Histogram `yaml:"histograms"`
}

// Counter is a metric defining prometheus counter
type Counter struct {
	Name           string        `yaml:"name"`
	Help           string        `yaml:"help"`
	PerfEventArray bool          `yaml:"perf_event_array"`
	FlushInterval  time.Duration `yaml:"flush_interval"`
	Labels         []Label       `yaml:"labels"`
}

// Histogram is a metric defining prometheus histogram
type Histogram struct {
	Name             string              `yaml:"name"`
	Help             string              `yaml:"help"`
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
	HistogramBucketExp2 HistogramBucketType = "exp2"
	// HistogramBucketExp2WithZero means histograms with power-of-two keys where the first key is for zero
	HistogramBucketExp2WithZero HistogramBucketType = "exp2zero"
	// HistogramBucketLinear means histogram with linear keys
	HistogramBucketLinear HistogramBucketType = "linear"
	// HistogramBucketFixed means histogram with fixed user-defined keys
	HistogramBucketFixed HistogramBucketType = "fixed"
)

// ParseConfigs parses the named configs from the provided configs directory
func ParseConfigs(dir string, names []string) ([]Config, error) {
	configs := make([]Config, len(names))

	for i, name := range names {
		path := filepath.Join(dir, fmt.Sprintf("%s.yaml", name))

		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("error opening %q for config %q: %v", path, name, err)
		}

		defer f.Close()

		err = yaml.NewDecoder(f).Decode(&configs[i])
		if err != nil {
			return nil, fmt.Errorf("error parsing %q for config %q: %v", path, name, err)
		}

		configs[i].Name = name

		err = validateConfig(&configs[i])
		if err != nil {
			return nil, fmt.Errorf("error validating config: %v", err)
		}

		configs[i].BPFPath = filepath.Join(dir, fmt.Sprintf("%s.bpf.o", name))
	}

	return configs, nil
}

func validateConfig(cfg *Config) error {
	if cfg.Metrics.Counters == nil && cfg.Metrics.Histograms == nil {
		return fmt.Errorf("metrics are not defined for config %q", cfg.Name)
	}

	for _, counter := range cfg.Metrics.Counters {
		if counter.Name == "" {
			return fmt.Errorf("counter %q in config %q lacks name", counter.Name, cfg.Name)
		}

		if counter.Help == "" {
			return fmt.Errorf("counter %q in config %q lacks help", counter.Name, cfg.Name)
		}
	}

	for _, histogram := range cfg.Metrics.Histograms {
		if histogram.Name == "" {
			return fmt.Errorf("histogram %q in config %q lacks name", histogram.Name, cfg.Name)
		}

		if histogram.Help == "" {
			return fmt.Errorf("histogram %q in config %q lacks help", histogram.Name, cfg.Name)
		}
	}

	return nil
}
