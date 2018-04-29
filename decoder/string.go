package decoder

import (
	"fmt"

	"github.com/cloudflare/ebpf_exporter/config"
)

// String is a decoded that decodes strings coming from the kernel
type String struct{}

// Decode transforms strings coming from the kernel
func (s *String) Decode(in string, conf config.Decoder) (string, int, error) {
	var found bool
	var start, end, i int
	for i = 0; i < len(in); i++ {
		if in[i] == '"' {
			if !found {
				found = true
				start = i
			} else {
				end = i
			}
		}
		if start > 0 && end > 0 {
			break
		}
	}
	if !found {
		return in, len(in), nil
	}
	if end == 0 {
		return "", i, fmt.Errorf("mismatched quotes, start=%d end=%d", start, end)
	}
	return in[start+1 : end], end, nil
}
