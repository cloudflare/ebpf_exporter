package decoder

import (
	"bytes"
	"testing"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

func TestIfNameDecoder(t *testing.T) {
	cache := map[uint32][]byte{
		uint32(1):          []byte("lo"),
		uint32(2734686214): []byte("eth42"),
	}

	cases := []struct {
		in  []byte
		out []byte
	}{
		{
			in:  []byte{0x1, 0x0, 0x0, 0x0},
			out: []byte("lo"),
		},
		{
			in:  []byte{0x6, 0x0, 0x0, 0xa3},
			out: []byte("eth42"),
		},
		{
			in:  []byte{0x0, 0x0, 0x0, 0x0},
			out: []byte("unknown:0"),
		},
	}

	for _, c := range cases {
		d := &IfName{cache: cache}

		out, err := d.Decode(c.in, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v: %v", c.in, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %s, got %s", c.out, out)
		}
	}
}
