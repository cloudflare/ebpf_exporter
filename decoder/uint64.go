package decoder

import (
	"strconv"

	"github.com/cloudflare/ebpf_exporter/config"
)

// UInt64 is a decoder that transforms hex numbers into regular numbers
type UInt64 struct{}

// Decode transforms hex numbers into regular numbers
func (u *UInt64) Decode(in string, conf config.Decoder) (string, error) {
	num, err := strconv.ParseUint(in, 0, 64)
	if err != nil {
		return "", err
	}

	return strconv.Itoa(int(num)), nil
}
