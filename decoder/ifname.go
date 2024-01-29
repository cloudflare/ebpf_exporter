package decoder

import (
	"fmt"
	"net"

	"github.com/cloudflare/ebpf_exporter/v2/config"
	"github.com/cloudflare/ebpf_exporter/v2/util"
)

// IfName is a decoder that transforms a network interface index into its name.
type IfName struct {
	cache map[uint32][]byte
}

// Decode transforms a network interface index into a name like "ens10".
func (i *IfName) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	if i.cache == nil {
		i.cache = make(map[uint32][]byte)
	}

	// Interface index is a uint32.
	idx := util.GetHostByteOrder().Uint32(in[0:4])

	if name, ok := i.cache[idx]; ok {
		return name, nil
	}

	iface, err := net.InterfaceByIndex(int(idx))
	if err != nil {
		// The interface might have been deleted since the metric was last
		// written. Unfortunately, in case the interface index is not in use
		// [net.InterfaceByIndex] does not return a unique error value that can
		// be compared with.
		return []byte(fmt.Sprintf("unknown:%d", idx)), nil
	}

	name := []byte(iface.Name)
	i.cache[idx] = name

	return name, nil
}
