package decoder

import (
	"fmt"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

// Hex is a decoder that decodes raw bytes into their hex string representation
type Hex struct{}

// Decode transforms bytes into their hex string representation
func (u *Hex) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	return []byte(fmt.Sprintf("%x", in)), nil
}
