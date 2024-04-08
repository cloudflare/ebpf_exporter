package decoder

import (
	"bytes"
	"testing"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

func TestErrnoDecoder(t *testing.T) {
	cases := []struct {
		in  []byte
		out []byte
	}{
		{
			in:  []byte("0"),
			out: []byte("unknown:0"),
		},
		{
			in:  []byte("1"),
			out: []byte("EPERM"),
		},
		{
			in:  []byte("32"),
			out: []byte("EPIPE"),
		},
		{
			in:  []byte("104"),
			out: []byte("ECONNRESET"),
		},
		{
			in:  []byte("1000"),
			out: []byte("unknown:1000"),
		},
	}

	for _, c := range cases {
		d := &Errno{}

		out, err := d.Decode(c.in, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v to %#v: %s", c.in, c.out, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %s, got %s", string(c.out), string(out))
		}
	}
}
