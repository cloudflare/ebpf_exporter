package decoder

import (
	"fmt"
	"strconv"
	"syscall"

	"github.com/cloudflare/ebpf_exporter/v2/config"
	"golang.org/x/sys/unix"
)

// Errno is a decoder that transforms unsigned errno integers into their string values
type Errno struct{}

// Decode transforms unsigned errno integers into their string values
func (e *Errno) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	errno, err := strconv.ParseUint(string(in), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("error parsing %q as uint", string(in))
	}

	name := unix.ErrnoName(syscall.Errno(errno))
	if name == "" {
		name = fmt.Sprintf("unknown:%d", errno)
	}

	return []byte(name), nil
}
