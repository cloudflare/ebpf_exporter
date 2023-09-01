package decoder

import (
	"testing"
)

func TestPCIDeviceDecoderMissing(t *testing.T) {
	testPCIMissing(t, &PCIDevice{}, [][]byte{
		[]byte("2156269568"), // 0x80861000
		[]byte("268596191"),  // 0x100273df
		[]byte("282994436"),  // 0x10de2704
	})
}

func TestPCIDeviceDecoderPresent(t *testing.T) {
	testPCIPresent(t, &PCIDevice{}, []pciCase{
		{
			in:  []byte("2156269568"), // 0x80861000
			out: []byte("82542 Gigabit Ethernet Controller (Fiber)"),
		},
		{
			in:  []byte("268596191"), // 0x100273df
			out: []byte("Navi 22 [Radeon RX 6700/6700 XT/6750 XT / 6800M/6850M XT]"),
		},
		{
			in:  []byte("282994436"), // 0x10de2704
			out: []byte("AD103 [GeForce RTX 4080]"),
		},
		{
			in:  []byte("364056607"), // 0x15b3101f
			out: []byte("MT2894 Family [ConnectX-6 Lx]"),
		},
		{
			in:  []byte("340633610"), // 0x144da80a
			out: []byte("NVMe SSD Controller PM9A1/PM9A3/980PRO"),
		},
		{
			in:  []byte("350492180"), // 0x14e41614
			out: []byte("BCM57454 NetXtreme-E 10Gb/25Gb/40Gb/50Gb/100Gb Ethernet"),
		},
		{
			in:  []byte("3735928559"), // 0xdeadbeef
			out: []byte("unknown pci device: 0xdeadbeef"),
		},
	})
}
