package decoder

import (
	"fmt"
	"strconv"

	"github.com/cloudflare/ebpf_exporter/config"
	"github.com/iovisor/gobpf/bcc"
)

// UInt is a decoder that transforms unsigned integers into their string values
type UInt struct{}

// Decode transforms unsigned integers into their string values
func (u *UInt) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	byteOrder := bcc.GetHostByteOrder()

	result := uint64(0)

	switch len(in) {
	case 8:
		result = byteOrder.Uint64(in)
	case 4:
		result = uint64(byteOrder.Uint32(in))
	case 2:
		result = uint64(byteOrder.Uint16(in))
	case 1:
		result = uint64(in[0])
	default:
		return nil, fmt.Errorf("unknown value length %d for %#v", len(in), in)
	}

	return []byte(strconv.Itoa(int(result))), nil
}
