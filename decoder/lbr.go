package decoder

import (
	"fmt"
	"strings"

	"github.com/cloudflare/ebpf_exporter/v2/config"
	"github.com/cloudflare/ebpf_exporter/v2/kallsyms"
	"github.com/cloudflare/ebpf_exporter/v2/util"
)

// struct perf_branch_entry is 24 bytes
const perfBranchEntrySize = 24

// LBR is a decoder that transforms LBR entry array into a stack
type LBR struct {
	decoder *kallsyms.Decoder
}

// Decode transforms LBR entry array into a stack
func (l *LBR) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	if len(in) == 0 {
		return []byte("<empty>"), nil
	}

	byteOrder := util.GetHostByteOrder()

	lines := make([]string, len(in)/perfBranchEntrySize)

	for i := range lines {
		from := uintptr(byteOrder.Uint64(in[i*24 : i*24+8]))
		to := uintptr(byteOrder.Uint64(in[i*24+8 : i*24+16]))

		lines[i] = fmt.Sprintf("0x%08x -> 0x%08x | %s -> %s", from, to, l.decoder.Sym(from), l.decoder.Sym(to))
	}

	return []byte(strings.Join(lines, "\n")), nil
}
