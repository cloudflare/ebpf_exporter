package decoder

import (
	"log"
	"os"
	"strings"

	"github.com/jaypipes/pcidb"
)

const missingPciIDsText = "missing pci.ids db"

var pciIDsPaths = []string{"/usr/share/misc/pci.ids", "/usr/share/hwdata/pci.ids"}
var pci *pcidb.PCIDB

func init() {
	for _, path := range pciIDsPaths {
		if _, err := os.Stat(path); err != nil {
			continue
		}

		db, err := pcidb.New()
		if err != nil {
			log.Fatalf("Error initializing PCI DB: %v", err)
		}

		pci = db

		return
	}

	log.Printf("None of the PCI DB paths (%s) are accessible, PCI decoders will return empty data", strings.Join(pciIDsPaths, ", "))
}
