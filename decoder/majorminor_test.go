package decoder

import (
	"bytes"
	"testing"

	"github.com/cloudflare/ebpf_exporter/config"
)

func TestMajorMinorDecoder(t *testing.T) {
	cases := []struct {
		in    []byte
		cache map[uint64][]byte
		out   []byte
	}{
		{
			in:    []byte{0x0, 0x8, 0x0, 0x0},
			cache: map[uint64][]byte{uint64(2048): []byte("sda"), uint64(2064): []byte("sdb")},
			out:   []byte("sda"),
		},
		{
			in:    []byte{0x10, 0x8, 0x0, 0x0},
			cache: map[uint64][]byte{uint64(2048): []byte("sda"), uint64(2064): []byte("sdb")},
			out:   []byte("sdb"),
		},
		{
			in:    []byte{0x10, 0x88, 0x0, 0x0},
			cache: map[uint64][]byte{uint64(2048): []byte("sda")},
			out:   []byte("unknown:136:16"),
		},
	}

	for _, c := range cases {
		d := &MajorMinor{cache: c.cache}

		out, err := d.Decode(c.in, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v with cache set to %#v: %s", c.in, c.cache, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %s, got %s", c.out, out)
		}
	}
}
