package decoder

import (
	"bytes"
	"testing"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

func TestPCISubClassDecoderMissing(t *testing.T) {
	if pci != nil {
		t.Skip("PCI DB is available")
	}

	cases := [][]byte{
		[]byte("5"),
		[]byte("264"),
		[]byte("512"),
	}

	for _, c := range cases {
		d := &PCISubClass{}

		out, err := d.Decode(c, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v: %v", c, err)
		}

		if !bytes.Equal(out, []byte(missingPciIdsText)) {
			t.Errorf("Expected %q, got %s", missingPciIdsText, out)
		}
	}
}

func TestPCISubClassDecoderPresent(t *testing.T) {
	if pci == nil {
		t.Skip("PCI DB is not available")
	}

	cases := []struct {
		in  []byte
		out []byte
	}{
		{
			in:  []byte("5"), // 0x0005
			out: []byte("Image coprocessor"),
		},
		{
			in:  []byte("264"), // 0x0108
			out: []byte("Non-Volatile memory controller"),
		},
		{
			in:  []byte("512"), // 0x0200
			out: []byte("Ethernet controller"),
		},
		{
			in:  []byte("770"), // 0x0302
			out: []byte("3D controller"),
		},
		{
			in:  []byte("3075"), // 0x0c03
			out: []byte("USB controller"),
		},
		{
			in:  []byte("1536"), // 0x0600
			out: []byte("Host bridge"),
		},
		{
			in:  []byte("1540"), // 0x0604
			out: []byte("PCI bridge"),
		},
		{
			in:  []byte("64768"), // 0xfd00
			out: []byte("unknown pci class: 0xfd"),
		},
		{
			in:  []byte("267"), // 0x010b
			out: []byte("unknown pci subclass: 0x0b (class 0x01)"),
		},
		{
			in:  []byte("3"), // 0x0003
			out: []byte("unknown pci subclass: 0x03 (class 0x00)"),
		},
	}

	for _, c := range cases {
		d := &PCISubClass{}

		out, err := d.Decode(c.in, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v: %v", c.in, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %q, got %q", c.out, out)
		}
	}
}
