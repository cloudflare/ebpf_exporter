package decoder

import (
	"fmt"
	"strconv"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

type Syscall struct{}

func (s *Syscall) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	number, err := strconv.Atoi(string(in))
	if err != nil {
		return nil, err
	}

	return []byte(resolveSyscall(uint64(number))), nil
}

func resolveSyscall(number uint64) string {
	if name, ok := syscalls[number]; ok {
		return name
	} else {
		return fmt.Sprintf("unknown_syscall:%d", number)
	}
}
