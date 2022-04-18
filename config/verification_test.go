package config

import (
	"strings"
	"testing"

	"github.com/hashicorp/go-version"
	"gopkg.in/yaml.v2"
)

var testKernelVersion = version.Must(version.NewVersion("0.0.0"))

func TestConfigVerificationFailure(t *testing.T) {
	reader := strings.NewReader(`programs:
  - name: timers
    metrics:
      counters:
        - name: timer_start_total
          help: Timers fired in the kernel
          table: counts
          labels:
            - name: function
              size: 8
              decoders:
                - name: ksym
`)
	config := Config{}

	err := yaml.NewDecoder(reader).Decode(&config)
	if err != nil {
		t.Errorf("failed to unmarshal config")
	}

	err = ValidateConfig(&config, testKernelVersion)
	if err != nil {
		t.Errorf("unexpected error validating config")
	}

	if config.Programs[0].Enabled {
		t.Errorf("program should be disabled since it failed validation")
	}
}

func TestConfigVerificationSuccess(t *testing.T) {
	reader := strings.NewReader(`programs:
  - name: timers
    metrics:
      counters:
        - name: timer_start_total
          help: Timers fired in the kernel
          table: counts
          labels:
            - name: function
              size: 8
              decoders:
                - name: ksym
    tracepoints:
      timer:timer_start: tracepoint__timer__timer_start
    code: |
      BPF_HASH(counts, u64);

      // Generates function tracepoint__timer__timer_start
      TRACEPOINT_PROBE(timer, timer_start) {
          counts.increment((u64) args->function);
          return 0;
      }
`)
	config := Config{}

	err := yaml.NewDecoder(reader).Decode(&config)
	if err != nil {
		t.Errorf("failed to unmarshal config")
	}

	err = ValidateConfig(&config, testKernelVersion)
	if err != nil {
		t.Errorf("unexpected failure validating config")
	}
}
