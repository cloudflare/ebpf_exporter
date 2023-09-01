package decoder

import (
	"fmt"
	"strconv"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

// PCIClass is a decoder that transforms PCI class id into a name
type PCIClass struct{}

// Decode transforms PCI class id into a name
func (d *PCIClass) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	if pci == nil {
		return []byte(missingPciIdsText), nil
	}

	num, err := strconv.Atoi(string(in))
	if err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%02x", num)

	if device, ok := pci.Classes[key]; ok {
		return []byte(device.Name), nil
	}

	return []byte(fmt.Sprintf("unknown pci class: 0x%s", key)), nil
}
