package decoder

import (
	"fmt"
	"strconv"

	"github.com/cloudflare/ebpf_exporter/config"
)

// KSym is a decoder that transforms kernel address to a function name
type KSym struct {
	cache map[string]string
}

// Decode transforms kernel address to a function name
func (k *KSym) Decode(in string, conf config.Decoder) (string, int, error) {
	if k.cache == nil {
		k.cache = map[string]string{}
	}

	var val string
	if _, err := fmt.Sscan(in, &val); err != nil {
		return "", 0, err
	}

	num, err := strconv.ParseUint(val, 0, 64)
	if err != nil {
		return fmt.Sprintf("invalid:%s", val), len(val), err
	}
	sym := fmt.Sprintf("%x", num-1)

	if _, ok := k.cache[sym]; !ok {
		name, err := Ksym(sym)
		if err != nil {
			return fmt.Sprintf("unknown:%s", sym), len(val), nil
		}

		k.cache[sym] = name
	}

	return k.cache[sym], len(val), nil
}
