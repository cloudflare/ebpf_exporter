package decoder

import (
	"bytes"
	"testing"

	"github.com/cloudflare/ebpf_exporter/config"
)

func TestStringDecoder(t *testing.T) {
	cases := []struct {
		in  []byte
		out []byte
	}{
		{
			in:  []byte("regular string"),
			out: []byte("regular string"),
		},
		{
			in:  append([]byte("null terminated string"), append([]byte{0x0}, []byte("bananas after null")...)...),
			out: []byte("null terminated string"),
		},
	}

	for _, c := range cases {
		d := &String{}

		out, err := d.Decode(c.in, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v to %#v: %s", c.in, c.out, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %s, got %s", c.out, out)
		}
	}
}
