package decoder

import (
	"errors"
	"fmt"

	"github.com/cloudflare/ebpf_exporter/config"
)

// ErrSkipLabelSet instructs exporter to skip label set
var ErrSkipLabelSet = errors.New("this label set should be skipped")

// Decoder transforms one string value into anoter string value
type Decoder interface {
	Decode(string, config.Decoder) (string, error)
}

// Set is a set of decoders that may be applied to produce a label
type Set struct {
	decoders map[string]Decoder
}

// NewSet creates a Set with all known decoders
func NewSet() *Set {
	return &Set{
		decoders: map[string]Decoder{
			"ksym":       &KSym{},
			"regexp":     &Regexp{},
			"static_map": &StaticMap{},
			"string":     &String{},
			"uint64":     &UInt64{},
		},
	}
}

// Decode transforms input string according to label configuration
func (s *Set) Decode(in string, label config.Label) (string, error) {
	result := in

	for _, decoder := range label.Decoders {
		if _, ok := s.decoders[decoder.Name]; !ok {
			return result, fmt.Errorf("unknown decoder %q", decoder.Name)
		}

		decoded, err := s.decoders[decoder.Name].Decode(result, decoder)
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
