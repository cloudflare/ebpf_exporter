package decoder

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/cloudflare/ebpf_exporter/config"
)

func TestStaticMapDecoder(t *testing.T) {
	cases := []struct {
		in      []byte
		mapping map[string]string
		out     []byte
	}{
		{
			in:      []byte(strconv.Itoa(int(1))),
			mapping: map[string]string{"1": "read", "2": "write"},
			out:     []byte("read"),
		},
		{
			in:      []byte(strconv.Itoa(int(2))),
			mapping: map[string]string{"1": "read", "2": "write"},
			out:     []byte("write"),
		},
		{
			in:      []byte(strconv.Itoa(int(3))),
			mapping: map[string]string{"1": "read", "2": "write"},
			out:     []byte("unknown:3"),
		},
	}

	for _, c := range cases {
		d := &StaticMap{}

		out, err := d.Decode(c.in, config.Decoder{StaticMap: c.mapping})
		if err != nil {
			t.Errorf("Error decoding %#v with mapping set to %#v: %s", c.in, c.mapping, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %s, got %s", c.out, out)
		}
	}
}

func TestStaticMapDecoderAllowUnknown(t *testing.T) {
	cases := []struct {
		in           []byte
		mapping      map[string]string
		allowUnknown bool
		out          []byte
	}{
		{
			in:           []byte(strconv.Itoa(int(3))),
			mapping:      map[string]string{"1": "read", "2": "write"},
			allowUnknown: true,
			out:          []byte("3"),
		},
		{
			in:           []byte(strconv.Itoa(int(3))),
			mapping:      map[string]string{"1": "read", "2": "write"},
			allowUnknown: false,
			out:          []byte("unknown:3"),
		},
	}

	for _, c := range cases {
		d := &StaticMap{}

		out, err := d.Decode(c.in, config.Decoder{StaticMap: c.mapping, AllowUnknown: c.allowUnknown})
		if err != nil {
			t.Errorf("Error decoding %#v with mapping set to %#v: %s", c.in, c.mapping, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %s, got %s", c.out, out)
		}
	}
}
