package decoder

import (
	"bytes"
	"testing"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

func TestHexDecoder(t *testing.T) {
	cases := []struct {
		in  []byte
		out []byte
	}{
		{
			in:  []byte{0x1},
			out: []byte("01"),
		},
		{
			in:  []byte{0x1, 0x2},
			out: []byte("0102"),
		},
		{
			in:  []byte{0xde, 0xad, 0xbe, 0xef},
			out: []byte("deadbeef"),
		},
	}

	for _, c := range cases {
		d := &Hex{}

		out, err := d.Decode(c.in, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v to %q: %v", c.in, c.out, err)
			continue
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %q, got %q", string(c.out), string(out))
		}
	}
}
