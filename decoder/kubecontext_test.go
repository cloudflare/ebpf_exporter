package decoder

import (
	"bytes"
	"testing"

	"github.com/cloudflare/ebpf_exporter/config"
)

func TestKubePodNamespaceDecoder(t *testing.T) {
	cases := []struct {
		in  []byte
		out []byte
	}{
		{
			in:  []byte{0x1, 0x0, 0x0, 0x0},
			out: []byte("unknown"),
		},
	}

	for _, c := range cases {
		d := &KubePodNamespace{}

		out, err := d.Decode(c.in, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v to %#v: %s", c.in, c.out, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %#v, got %#v", c.out, out)
		}
	}
}
