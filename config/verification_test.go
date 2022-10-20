package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestConfigVerificationSuccess(t *testing.T) {
	reader := strings.NewReader(`programs:
  - name: timers
    metrics:
      counters:
        - name: timer_start_total
          help: Timers fired in the kernel
          map: counts
          labels:
            - name: function
              size: 8
              decoders:
                - name: ksym
    tracepoints:
      timer:timer_start: tracepoint__timer__timer_start
`)
	config := Config{}

	err := yaml.NewDecoder(reader).Decode(&config)
	if err != nil {
		t.Errorf("failed to unmarshal config")
	}

	err = ValidateConfig(&config)
	if err != nil {
		t.Errorf("unexpected failure validating config")
	}
}
