package decoder

import (
	"fmt"
	"strconv"

	"github.com/cloudflare/ebpf_exporter/config"
)

// UInt64 is a decoder that transforms hex numbers into regular numbers
type UInt64 struct{}

// Decode transforms hex numbers into regular numbers
func (u *UInt64) Decode(in string, conf config.Decoder) (string, int, error) {
	var val string
	if _, err := fmt.Sscan(in, &val); err != nil {
		return "", 0, err
	}
	num, err := strconv.ParseUint(val, 0, 64)
	if err != nil {
		return "", 0, err
	}

	return strconv.Itoa(int(num)), len(val), nil
}
