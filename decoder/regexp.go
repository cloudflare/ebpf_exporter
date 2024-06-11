package decoder

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

// Regexp is a decoder that only allows inputs matching regexp
type Regexp struct {
	cache map[string]*regexp.Regexp
}

// Decode only allows inputs matching regexp
func (r *Regexp) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	if conf.Regexps == nil {
		return nil, errors.New("no regexps defined in config")
	}

	if r.cache == nil {
		r.cache = map[string]*regexp.Regexp{}
	}

	for _, expr := range conf.Regexps {
		if _, ok := r.cache[expr]; !ok {
			compiled, err := regexp.Compile(expr)
			if err != nil {
				return nil, fmt.Errorf("error compiling regexp %q: %s", expr, err)
			}

			r.cache[expr] = compiled
		}

		matches := r.cache[expr].FindSubmatch(in)

		// First sub-match if present
		if len(matches) == 2 {
			return matches[1], nil
		}

		// General match
		if len(matches) == 1 {
			return matches[0], nil
		}
	}

	return nil, ErrSkipLabelSet
}
