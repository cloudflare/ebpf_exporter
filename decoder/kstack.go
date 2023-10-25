package decoder

import (
	"strings"

	"github.com/cloudflare/ebpf_exporter/v2/config"
	"github.com/cloudflare/ebpf_exporter/v2/kallsyms"
	"github.com/cloudflare/ebpf_exporter/v2/util"
)

// KStack is a decoder that transforms an array of kernel frame addresses to a newline separated stack of symbols
type KStack struct {
	decoder *kallsyms.Decoder
}

// Decode transforms an array of kernel frame addresses to a newline separated stack of symbols
func (k *KStack) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	addrs := []uintptr{}
	for off := 0; off < len(in); off += 8 {
		ptr := util.GetHostByteOrder().Uint64(in[off : off+8])
		if ptr == 0 {
			break
		}

		addrs = append(addrs, uintptr(ptr))
	}

	stack := make([]string, len(addrs))
	for i, frame := range k.decoder.Stack(addrs) {
		if frame.Sym == "" {
			stack[i] = "??"
		} else {
			stack[i] = frame.Sym
		}
	}

	return []byte(strings.Join(stack, "\n")), nil
}
