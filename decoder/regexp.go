package decoder

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/cloudflare/ebpf_exporter/config"
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

	matched := false

	for _, expr := range conf.Regexps {
		if _, ok := r.cache[expr]; !ok {
			compiled, err := regexp.Compile(expr)
			if err != nil {
				return nil, fmt.Errorf("error compiling regexp %q: %s", expr, err)
			}

			r.cache[expr] = compiled
		}

		if r.cache[expr].MatchString(string(in)) {
			matched = true
			break
		}
	}

	if !matched {
		return nil, ErrSkipLabelSet
	}

	return in, nil
}
