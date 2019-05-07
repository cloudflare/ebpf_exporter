package decoder

import (
	"github.com/cloudflare/ebpf_exporter/config"
)

// String is a decoder that decodes strings coming from the kernel
type String struct{}

// Decode transforms byte slice from the kernel into string
func (s *String) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	return in[0:clen(in)], nil
}

// clen returns position of the fist null byte in a byte slice or byte slice
// length if there is no null byte in the slice
func clen(n []byte) int {
	for i := 0; i < len(n); i++ {
		if n[i] == 0 {
			return i
		}
	}

	return len(n)
}
