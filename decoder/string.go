package decoder

import (
	"strings"

	"github.com/cloudflare/ebpf_exporter/config"
)

// String is a decoded that decodes strings coming from the kernel
type String struct{}

// Decode transforms strings coming from the kernel
func (s *String) Decode(in string, conf config.Decoder) (string, error) {
	return strings.Trim(in, "\""), nil
}
