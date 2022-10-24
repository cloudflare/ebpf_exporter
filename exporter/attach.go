package exporter

import (
	"log"

	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/config"
)

func attachModule(module *libbpfgo.Module, program config.Program) (map[*libbpfgo.BPFProg]bool, error) {
	attached := map[*libbpfgo.BPFProg]bool{}

	iter := module.Iterator()
	for {
		prog := iter.NextProgram()
		if prog == nil {
			break
		}

		_, err := prog.AttachGeneric()
		if err != nil {
			log.Printf("Failed to attach program %q for %q: %v", prog.Name(), program.Name, err)
			attached[prog] = false
		} else {
			attached[prog] = true
		}
	}

	return attached, nil
}
