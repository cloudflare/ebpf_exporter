package decoder

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/cloudflare/ebpf_exporter/v2/config"
	lru "github.com/hashicorp/golang-lru/v2"
)

// Regexp is a decoder that only allows inputs matching regexp
type Regexp struct {
	cache     map[string]*regexp.Regexp
	skipCache *lru.Cache[string, struct{}]
}

// Decode only allows inputs matching regexp
func (r *Regexp) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	if conf.Regexps == nil {
		return nil, errors.New("no regexps defined in config")
	}
	inputStr := string(in)

	if r.cache == nil {
		r.cache = map[string]*regexp.Regexp{}
	}
	if conf.SkipCacheSize > 0 && r.skipCache == nil {
		skipCache, err := lru.New[string, struct{}](int(conf.SkipCacheSize))
		if err != nil {
			return nil, err
		}
		r.skipCache = skipCache
	}

	for _, expr := range conf.Regexps {
		if _, ok := r.cache[expr]; !ok {
			compiled, err := regexp.Compile(expr)
			if err != nil {
				return nil, fmt.Errorf("error compiling regexp %q: %w", expr, err)
			}

			r.cache[expr] = compiled
		}

		if r.skipCache != nil {
			if _, ok := r.skipCache.Get(inputStr); ok {
				return nil, ErrSkipLabelSet
			}
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

	if r.skipCache != nil {
		r.skipCache.Add(inputStr, struct{}{})
	}

	return nil, ErrSkipLabelSet
}
