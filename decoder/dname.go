package decoder

import (
	"github.com/cloudflare/ebpf_exporter/config"
)

// Dname is a decoder that decodes DNS qname wire format
type Dname struct{}

// Decode transforms wire format into string
func (d *Dname) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	if len(in) == 0 {
		return []byte("."), nil
	}

	out := make([]byte, len(in))
	for off := 0; off < len(in); {
		n := int(in[off])
		// change length byte into "."
		out[off] = '.'
		off++
		if off+n > len(in) {
			return in, nil
		}

		copy(out[off:off+n], in[off:off+n])
		off += n
	}

	// ignore the leading "."
	return out[1:], nil
}
