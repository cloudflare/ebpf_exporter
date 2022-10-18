package libbpfgo

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"strings"
)

type Symbol struct {
	name   string
	size   int
	offset int

	sectionName string
	byteOrder   binary.ByteOrder
}

func getGlobalVariableSymbol(elf *elf.File, varName string) (*Symbol, error) {
	regularSymbols, err := elf.Symbols()
	if err != nil {
		return nil, err
	}

	var symbols []Symbol
	for _, s := range regularSymbols {
		i := int(s.Section)
		if i >= len(elf.Sections) {
			continue
		}
		sectionName := elf.Sections[i].Name
		if isGlobalVariableSection(sectionName) {
			symbols = append(symbols, Symbol{
				name:        s.Name,
				size:        int(s.Size),
				offset:      int(s.Value),
				sectionName: sectionName,
				byteOrder:   elf.ByteOrder,
			})
		}
	}

	for _, s := range symbols {
		if s.name == varName {
			return &s, nil
		}
	}

	return nil, errors.New("symbol not found")
}

func isGlobalVariableSection(sectionName string) bool {
	if sectionName == ".data" || sectionName == ".rodata" {
		return true
	}
	if strings.HasPrefix(sectionName, ".data.") ||
		strings.HasPrefix(sectionName, ".rodata.") {
		return true
	}
	return false
}
