package decoder

import (
	"testing"
)

func TestPCIVendorDecoderMissing(t *testing.T) {
	testPCIMissing(t, &PCIVendor{}, [][]byte{
		[]byte("32902"), // 0x8086
		[]byte("4098"),  // 0x1002
		[]byte("4318"),  // 0x10de
	})
}

func TestPCIVendorDecoderPresent(t *testing.T) {
	testPCIPresent(t, &PCIVendor{}, []pciCase{
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
	})
}
