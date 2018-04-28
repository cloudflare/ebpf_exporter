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
func (r *Regexp) Decode(in string, conf config.Decoder) (string, int, error) {
	if conf.Regexps == nil {
		return "", 0, errors.New("no regexps defined in config")
	}

	if r.cache == nil {
		r.cache = map[string]*regexp.Regexp{}
	}

	var matchedLocation []int
	for _, expr := range conf.Regexps {
		if _, ok := r.cache[expr]; !ok {
			compiled, err := regexp.Compile(expr)
			if err != nil {
				return "", 0, fmt.Errorf("error compiling regexp %q: %s", expr, err)
			}

			r.cache[expr] = compiled
		}

		matchedLocation = r.cache[expr].FindStringIndex(in)
		if matchedLocation != nil {
			break
		}
	}
	if matchedLocation != nil {
		return in[matchedLocation[0]:matchedLocation[1]], matchedLocation[1] - matchedLocation[0], nil
	}
	return "", 0, ErrSkipLabelSet
}
