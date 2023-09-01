package decoder

import (
	"fmt"
	"strconv"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

// PCIDevice2 is a decoder that transforms PCI device id into a name
type PCIDevice struct{}

// Decode transforms PCI device id into a name
func (d *PCIDevice) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	if pci == nil {
		return []byte(missingPciIdsText), nil
	}

	num, err := strconv.Atoi(string(in))
	if err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%04x", num)

	if device, ok := pci.Products[key]; ok {
		return []byte(device.Name), nil
	} else {
		return []byte(fmt.Sprintf("unknown pci device: 0x%s", key)), nil
	}
}
