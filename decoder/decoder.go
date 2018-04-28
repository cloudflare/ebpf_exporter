package decoder

import (
	"errors"
	"fmt"

	"github.com/cloudflare/ebpf_exporter/config"
)

// ErrSkipLabelSet instructs exporter to skip label set
var ErrSkipLabelSet = errors.New("this label set should be skipped")

// Decoder transforms value into another string value and
// return the number of runes it decoded
type Decoder interface {
	Decode(string, config.Decoder) (string, int, error)
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
func (s *Set) Decode(in string, label config.Label) (input string, index int, err error) {
	input = in
	var advanced bool
	for _, decoder := range label.Decoders {
		if _, ok := s.decoders[decoder.Name]; !ok {
			return input, index, fmt.Errorf("unknown decoder %q", decoder.Name)
		}

		var i int
		input, i, err = s.decoders[decoder.Name].Decode(input, decoder)
		if err != nil {
			if err == ErrSkipLabelSet {
				return input, index, err
			}
			return input, index, fmt.Errorf("error decoding with decoder %q: %s", decoder.Name, err)
		}
		// only advance index once when we get the first meaningful pass out of the
		// original input. The rest of the decoders will not change index.
		if i > 0 && !advanced {
			index = i
		}
	}

	return input, index, nil
}
