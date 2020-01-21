package decoder

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cloudflare/ebpf_exporter/config"
)

// ErrSkipLabelSet instructs exporter to skip label set
var ErrSkipLabelSet = errors.New("this label set should be skipped")

// Decoder transforms byte field value into a byte value representing string
// to either use as an input for another Decoder or to use as the final
// label value for Prometheus metrics
type Decoder interface {
	Decode([]byte, config.Decoder) ([]byte, error)
}

// Set is a set of Decoders that may be applied to produce a label
type Set struct {
	mu       sync.Mutex
	decoders map[string]Decoder
}

// NewSet creates a Set with all known decoders
func NewSet() *Set {
	return &Set{
		decoders: map[string]Decoder{
			"cgroup":     &CGroup{},
			"ksym":       &KSym{},
			"majorminor": &MajorMinor{},
			"regexp":     &Regexp{},
			"static_map": &StaticMap{},
			"string":     &String{},
			"dname":      &Dname{},
			"uint":       &UInt{},
			"inet_ip":    &InetIP{},
		},
	}
}

// Decode transforms input byte field into a string according to configuration
func (s *Set) Decode(in []byte, label config.Label) ([]byte, error) {
	result := in

	for _, decoder := range label.Decoders {
		if _, ok := s.decoders[decoder.Name]; !ok {
			return result, fmt.Errorf("unknown decoder %q", decoder.Name)
		}

		s.mu.Lock()
		decoded, err := s.decoders[decoder.Name].Decode(result, decoder)
		s.mu.Unlock()
		if err != nil {
			if err == ErrSkipLabelSet {
				return decoded, err
			}
			return decoded, fmt.Errorf("error decoding with decoder %q: %s", decoder.Name, err)
		}

		result = decoded
	}

	return result, nil
}

// DecodeLabels transforms eBPF map key bytes into a list of label values
// according to configuration
func (s *Set) DecodeLabels(in []byte, labels []config.Label) ([]string, error) {
	values := make([]string, len(labels))

	off := uint(0)

	totalSize := uint(0)
	for _, label := range labels {
		size := label.Size
		if size == 0 {
			return nil, fmt.Errorf("error decoding label %q: size is zero or not set", label.Name)
		}

		totalSize += size
	}

	if totalSize != uint(len(in)) {
		return nil, fmt.Errorf("error decoding labels: total size of key %#v is %d bytes, but wehave labels to decode %d", in, len(in), totalSize)
	}

	for i, label := range labels {
		if len(label.Decoders) == 0 {
			return nil, fmt.Errorf("error decoding label %q: no decoders set", label.Name)
		}

		size := label.Size

		decoded, err := s.Decode(in[off:off+size], label)
		if err != nil {
			return nil, err
		}

		off += size

		values[i] = string(decoded)
	}

	return values, nil
}
