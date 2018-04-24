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
func (k *KSym) Decode(in string, conf config.Decoder) (string, error) {
	if k.cache == nil {
		k.cache = map[string]string{}
	}

	num, err := strconv.ParseUint(in, 0, 64)
	if err != nil {
		return fmt.Sprintf("invalid:%s", in), err
	}

	in = fmt.Sprintf("%x", num-1)

	if _, ok := k.cache[in]; !ok {
		name, err := Ksym(in)
		if err != nil {
			return fmt.Sprintf("unknown:%s", in), nil
		}

		k.cache[in] = name
	}

	return k.cache[in], nil
}
