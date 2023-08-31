package exporter

import (
	"log"

	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/v2/config"
)

func attachModule(module *libbpfgo.Module, cfg config.Config) map[*libbpfgo.BPFProg]bool {
	attached := map[*libbpfgo.BPFProg]bool{}

	iter := module.Iterator()
	for {
		prog := iter.NextProgram()
		if prog == nil {
			break
		}

		_, err := prog.AttachGeneric()
		if err != nil {
			log.Printf("Failed to attach program %q for config %q: %v", prog.Name(), cfg.Name, err)
			attached[prog] = false
		} else {
			attached[prog] = true
		}
	}

	return attached
}
