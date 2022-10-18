package libbpfgo

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"strings"
)

type Symbol struct {
	elf.Symbol

	Offset    int
	ByteOrder binary.ByteOrder
	Section   elf.Section
}

func getGlobalVarSymbol(elf *elf.File, name string) (*Symbol, error) {
	regularSymbols, err := elf.Symbols()
	if err != nil {
		return nil, err
	}

	var symbols []Symbol
	sectionPrefixes := []string{".rodata", ".data"}
	for _, s := range regularSymbols {
		i := int(s.Section)
		if i < len(elf.Sections) {
			name := elf.Sections[i].Name
			for _, prefix := range sectionPrefixes {
				if strings.HasPrefix(name, prefix) {
					symbols = append(symbols, Symbol{
						Symbol:    s,
						Offset:    int(s.Value),
						ByteOrder: elf.ByteOrder,
						Section:   *elf.Sections[i],
					})
				}
			}
		}
	}

	for _, s := range symbols {
		if s.Name == name {
			return &s, nil
		}
	}

	return nil, errors.New("symbol not found")
}
