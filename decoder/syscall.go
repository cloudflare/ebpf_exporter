package decoder

import (
	"fmt"
	"runtime"

	"github.com/cloudflare/ebpf_exporter/v2/config"
	"github.com/cloudflare/ebpf_exporter/v2/util"
)

//go:generate sh -c "perl mksysnum_linux.pl /usr/include/asm-generic/unistd.h aarch > syscalls_aarch64.go"
//go:generate sh -c "perl mksysnum_linux.pl /usr/include/asm/unistd_64.h x86 > syscalls_x86_64.go"

type Syscall struct{}

func (s *Syscall) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	byteOrder := util.GetHostByteOrder()

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

	return []byte(GetSyscall(result)), nil
}

func GetSyscall(syscallNum uint64) string {
	var syscall string

	switch runtime.GOARCH {
	case "amd64":
		if name, ok := x86_64_syscalls[syscallNum]; ok {
			syscall = name
		}
	case "arm64":
		if name, ok := aarch_64_syscalls[syscallNum]; ok {
			syscall = name
		}
	default:
		panic("unsupported arch")
	}

	if syscall == "" {
		return fmt.Sprintf("unknown_syscall:%d", syscallNum)
	}

	return syscall
}
