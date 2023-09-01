package decoder

import (
	"bytes"
	"testing"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

func TestPCIClassDecoderMissing(t *testing.T) {
	if pci != nil {
		t.Skip("PCI DB is available")
	}

	cases := [][]byte{
		[]byte("1"),
		[]byte("2"),
		[]byte("6"),
	}

	for _, c := range cases {
		d := &PCIClass{}

		out, err := d.Decode(c, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v: %v", c, err)
		}

		if !bytes.Equal(out, []byte(missingPciIdsText)) {
			t.Errorf("Expected %q, got %s", missingPciIdsText, out)
		}
	}
}

func TestPCIClassDecoderPresent(t *testing.T) {
	if pci == nil {
		t.Skip("PCI DB is not available")
	}

	cases := []struct {
		in  []byte
		out []byte
	}{
		{
			in:  []byte("1"),
			out: []byte("Mass storage controller"),
		},
		{
			in:  []byte("2"),
			out: []byte("Network controller"),
		},
		{
			in:  []byte("3"),
			out: []byte("Display controller"),
		},
		{
			in:  []byte("6"),
			out: []byte("Bridge"),
		},
		{
			in:  []byte("12"),
			out: []byte("Serial bus controller"),
		},
		{
			in:  []byte("253"),
			out: []byte("unknown pci class: 0xfd"),
		},
	}

	for _, c := range cases {
		d := &PCIClass{}

		out, err := d.Decode(c.in, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v: %v", c.in, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %q, got %q", c.out, out)
		}
	}
}
