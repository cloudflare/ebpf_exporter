package decoder

import (
	"testing"
)

func TestPCISubClassDecoderMissing(t *testing.T) {
	testPCIMissing(t, &PCISubClass{}, [][]byte{
		[]byte("5"),
		[]byte("264"),
		[]byte("512"),
	})
}

func TestPCISubClassDecoderPresent(t *testing.T) {
	testPCIPresent(t, &PCISubClass{}, []pciCase{
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
	})
}
