package decoder

import (
	"bytes"
	"testing"

	"github.com/cloudflare/ebpf_exporter/config"
)

func TestKsymDecoder(t *testing.T) {
	cases := []struct {
		in    []byte
		cache map[string][]byte
		out   []byte
	}{
		{
			in:    []byte{0x6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			cache: map[string][]byte{"6": []byte("call_six")},
			out:   []byte("call_six"),
		},
		{
			in:    []byte{0x6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			cache: map[string][]byte{"7": []byte("call_seven")},
			out:   []byte("unknown_addr:0x6"),
		},
	}

	for _, c := range cases {
		d := &KSym{cache: c.cache}

		out, err := d.Decode(c.in, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v with cache set to %#v: %s", c.in, c.cache, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %s, got %s", c.out, out)
		}
	}
}
