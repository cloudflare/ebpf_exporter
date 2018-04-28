package decoder

import (
	"fmt"

	"github.com/cloudflare/ebpf_exporter/config"
)

// StaticMap is a decoded that maps values according to a static map
type StaticMap struct{}

// Decode maps values according to a static map
func (s *StaticMap) Decode(in string, conf config.Decoder) (string, int, error) {
	// TODO: err?
	if conf.StaticMap == nil {
		return "empty mapping", 0, nil
	}

	var val string
	if _, err := fmt.Sscan(in, &val); err != nil {
		return "", 0, err
	}

	res, ok := conf.StaticMap[val]
	if !ok {
		// TODO: err?
		res = fmt.Sprintf("unknown:%s", val)
	}

	return res, len(val), nil
}
