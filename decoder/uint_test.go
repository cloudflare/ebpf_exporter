package decoder

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/cloudflare/ebpf_exporter/config"
)

func TestUIntDecoder(t *testing.T) {
	cases := []struct {
		in  []byte
		out []byte
	}{
		{
			in:  []byte{0x1},
			out: []byte(strconv.Itoa(int(1))),
		},
		{
			in:  []byte{0x2, 0x0},
			out: []byte(strconv.Itoa(int(2))),
		},
		{
			in:  []byte{0x4, 0x0, 0x0, 0x0},
			out: []byte(strconv.Itoa(int(4))),
		},
		{
			in:  []byte{0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			out: []byte(strconv.Itoa(int(8))),
		},
	}

	for _, c := range cases {
		d := &UInt{}

		out, err := d.Decode(c.in, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v to %#v: %s", c.in, c.out, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %#v, got %#v", c.out, out)
		}
	}
}
