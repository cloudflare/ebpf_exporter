package decoder

import (
	"testing"
)

func TestPCIClassDecoderMissing(t *testing.T) {
	testPCIMissing(t, &PCIClass{}, [][]byte{
		[]byte("1"),
		[]byte("2"),
		[]byte("6"),
	})
}

func TestPCIClassDecoderPresent(t *testing.T) {
	testPCIPresent(t, &PCIClass{}, []pciCase{
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
	})
}
