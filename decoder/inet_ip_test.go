package decoder

import (
	"bytes"
	"testing"

	"github.com/cloudflare/ebpf_exporter/config"
)

func TestInetIpDecoder(t *testing.T) {
	cases := []struct {
		in  []byte
		out []byte
	}{
		{
			in:  []byte{0x01, 0x02, 0x03, 0x04},
			out: []byte("1.2.3.4"),
		},
		{
			in: []byte{
				0x24, 0x00,
				0xcb, 0x00,
				0x00, 0x04,
				0x10, 0x24,
				0x00, 0x00,
				0x00, 0x00,
				0xa2, 0x9e,
				0xfd, 0x8f,
			},
			out: []byte("2400:cb00:4:1024::a29e:fd8f"),
		},
	}

	for _, c := range cases {
		d := &InetIP{}

		out, err := d.Decode(c.in, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v to %#v: %s", c.in, c.out, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %s, got %s", c.out, out)
		}
	}
}
