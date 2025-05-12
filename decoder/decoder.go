package decoder

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cloudflare/ebpf_exporter/v2/cgroup"
	"github.com/cloudflare/ebpf_exporter/v2/config"
	"github.com/cloudflare/ebpf_exporter/v2/kallsyms"
)

// ErrSkipLabelSet instructs exporter to skip label set
var ErrSkipLabelSet = errors.New("this label set should be skipped")

// Decoder transforms byte field value into a byte value representing string
// to either use as an input for another Decoder or to use as the final
// label value for Prometheus metrics
type Decoder interface {
	Decode(in []byte, conf config.Decoder) ([]byte, error)
}

// Set is a set of Decoders that may be applied to produce a label
type Set struct {
	mu       sync.Mutex
	decoders map[string]Decoder
	cache    map[string]map[string][]string
}

// NewSet creates a Set with all known decoders
func NewSet(monitor *cgroup.Monitor) (*Set, error) {
	ksym, err := kallsyms.NewDecoder("/proc/kallsyms")
	if err != nil {
		return nil, fmt.Errorf("error creating ksym decoder: %w", err)
	}

	return &Set{
		decoders: map[string]Decoder{
			"cgroup":       &CGroup{monitor},
			"dname":        &Dname{},
			"errno":        &Errno{},
			"hex":          &Hex{},
			"ifname":       &IfName{},
			"inet_ip":      &InetIP{},
			"kstack":       &KStack{ksym},
			"ksym":         &KSym{ksym},
			"majorminor":   &MajorMinor{},
			"pci_class":    &PCIClass{},
			"pci_device":   &PCIDevice{},
			"pci_subclass": &PCISubClass{},
			"pci_vendor":   &PCIVendor{},
			"regexp":       &Regexp{},
			"static_map":   &StaticMap{},
			"string":       &String{},
			"syscall":      &Syscall{},
			"uint":         &UInt{},
		},
		cache: map[string]map[string][]string{},
	}, nil
}

// decode transforms input byte field into a string according to configuration
func (s *Set) decode(in []byte, label config.Label) ([]byte, error) {
	result := in

	for _, decoder := range label.Decoders {
		if _, ok := s.decoders[decoder.Name]; !ok {
			return result, fmt.Errorf("unknown decoder %q", decoder.Name)
		}

		decoded, err := s.decoders[decoder.Name].Decode(result, decoder)
		if err != nil {
			if errors.Is(err, ErrSkipLabelSet) {
				return decoded, err
			}

			return decoded, fmt.Errorf("error decoding with decoder %q: %w", decoder.Name, err)
		}

		result = decoded
	}

	return result, nil
}

// DecodeLabelsForMetrics transforms eBPF map key bytes into a list of label values
// according to configuration (different label sets require different names).
// This decoder method variant does caching and is suitable for metrics.
func (s *Set) DecodeLabelsForMetrics(in []byte, name string, labels []config.Label) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cache, ok := s.cache[name]
	if !ok {
		cache = map[string][]string{}
		s.cache[name] = cache
	}

	// string(in) must not be a variable to avoid allocation:
	// * https://github.com/golang/go/commit/f5f5a8b6209f8
	if cached, ok := cache[string(in)]; ok {
		return cached, nil
	}

	values, err := s.decodeLabels(in, labels)
	if err != nil {
		return nil, err
	}

	cache[string(in)] = values

	return values, nil
}

// DecodeLabelsForTracing transforms eBPF map key bytes into a list of label values
// according to configuration (different label sets require different names).
// This decoder method variant does not do caching and is suitable for tracing.
func (s *Set) DecodeLabelsForTracing(in []byte, labels []config.Label) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.decodeLabels(in, labels)
}

// decodeLabels is the inner function of DecodeLabels without any caching
func (s *Set) decodeLabels(in []byte, labels []config.Label) ([]string, error) {
	values := make([]string, len(labels))

	off := uint(0)

	totalSize := uint(0)
	for _, label := range labels {
		size := label.Size
		if size == 0 {
			return nil, fmt.Errorf("error decoding label %q: size is zero or not set", label.Name)
		}

		totalSize += size + label.Padding
	}

	if totalSize != uint(len(in)) {
		return nil, fmt.Errorf("error decoding labels: total size of key %#v is %d bytes, but we have labels to decode %d", in, len(in), totalSize)
	}

	for i, label := range labels {
		if len(label.Decoders) == 0 {
			return nil, fmt.Errorf("error decoding label %q: no decoders set", label.Name)
		}

		size := label.Size

		decoded, err := s.decode(in[off:off+size], label)
		if err != nil {
			return nil, err
		}

		off += size + label.Padding

		values[i] = string(decoded)
	}

	return values, nil
}
