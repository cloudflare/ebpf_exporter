package decoder

import (
	"fmt"
	"strconv"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

// PCIVendor is a decoder that transforms PCI vendor id into a name
type PCIVendor struct{}

// Decode transforms PCI vendor id into a name
func (d *PCIVendor) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	if pci == nil {
		return []byte(missingPciIdsText), nil
	}

	num, err := strconv.Atoi(string(in))
	if err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%02x", num)

	if vendor, ok := pci.Vendors[key]; ok {
		return []byte(vendor.Name), nil
	}

	return []byte(fmt.Sprintf("unknown pci vendor: 0x%s", key)), nil
}
