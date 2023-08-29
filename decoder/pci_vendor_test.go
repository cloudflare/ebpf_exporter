package decoder

import (
	"bytes"
	"testing"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

func TestPCIVendorDecoderMissing(t *testing.T) {
	if pci != nil {
		t.Skip("PCI DB is available")
	}

	cases := [][]byte{
		[]byte("32902"), // 0x8086
		[]byte("4098"),  // 0x1002
		[]byte("4318"),  // 0x10de
	}

	for _, c := range cases {
		d := &PCIVendor{}

		out, err := d.Decode(c, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v: %v", c, err)
		}

		if !bytes.Equal(out, []byte(missingPciIdsText)) {
			t.Errorf("Expected %q, got %s", missingPciIdsText, out)
		}
	}
}

func TestPCIVendorDecoderPresent(t *testing.T) {
	if pci == nil {
		t.Skip("PCI DB is not available")
	}

	cases := []struct {
		in  []byte
		out []byte
	}{
		{
			in:  []byte("32902"), // 0x8086
			out: []byte("Intel Corporation"),
		},
		{
			in:  []byte("4098"), // 0x1002
			out: []byte("Advanced Micro Devices, Inc. [AMD/ATI]"),
		},
		{
			in:  []byte("4318"), // 0x10de
			out: []byte("NVIDIA Corporation"),
		},
		{
			in:  []byte("5555"), // 0x15b3
			out: []byte("Mellanox Technologies"),
		},
		{
			in:  []byte("5197"), // 0x144d
			out: []byte("Samsung Electronics Co Ltd"),
		},
		{
			in:  []byte("5348"), // 0x14e4
			out: []byte("Broadcom Inc. and subsidiaries"),
		},
		{
			in:  []byte("48879"), // 0xbeef
			out: []byte("unknown pci vendor: 0xbeef"),
		},
	}

	for _, c := range cases {
		d := &PCIVendor{}

		out, err := d.Decode(c.in, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v: %v", c.in, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %q, got %q", c.out, out)
		}
	}
}
