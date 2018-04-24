package decoder

import (
	"fmt"

	"github.com/cloudflare/ebpf_exporter/config"
)

// StaticMap is a decoded that maps values according to a static map
type StaticMap struct{}

// Decode maps values according to a static map
func (s *StaticMap) Decode(in string, conf config.Decoder) (string, error) {
	// TODO: err?
	if conf.StaticMap == nil {
		return "empty mapping", nil
	}

	value, ok := conf.StaticMap[in]
	if !ok {
		// TODO: err?
		return fmt.Sprintf("unknown:%s", in), nil
	}

	return value, nil
}
