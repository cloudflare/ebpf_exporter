package decoder

import (
	"fmt"
	"strconv"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

// PCISubClass is a decoder that transforms PCI class id into a name
type PCISubClass struct{}

// Decode transforms PCI class id into a name
func (d *PCISubClass) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	if pci == nil {
		return []byte(missingPciIdsText), nil
	}

	num, err := strconv.Atoi(string(in))
	if err != nil {
		return nil, err
	}

	classID := fmt.Sprintf("%02x", num>>8)

	if class, ok := pci.Classes[classID]; ok {
		subclassID := fmt.Sprintf("%02x", num&0xff)
		for _, subclass := range class.Subclasses {
			if subclass.ID == subclassID {
				return []byte(subclass.Name), nil
			}
		}

		return []byte(fmt.Sprintf("unknown pci subclass: 0x%s (class 0x%s)", subclassID, classID)), nil
	}

	return []byte(fmt.Sprintf("unknown pci class: 0x%s", classID)), nil
}
