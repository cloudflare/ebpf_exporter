package decoder

import (
	"log"
	"os"

	"github.com/jaypipes/pcidb"
)

const pciIdsPath = "/usr/share/misc/pci.ids"
const missingPciIdsText = "missing pci.ids db"

var pci *pcidb.PCIDB

func init() {
	if _, err := os.Stat(pciIdsPath); err != nil {
		log.Printf("PCI DB path %q is not accessible: %v", pciIdsPath, err)
		return
	}

	db, err := pcidb.New()
	if err != nil {
		log.Fatalf("Error initializing PCI DB: %v", err)
	}

	pci = db
}
