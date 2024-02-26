package exporter

import (
	"log"

	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/v2/config"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

func attachModule(span trace.Span, module *libbpfgo.Module, cfg config.Config) map[*libbpfgo.BPFProg]bool {
	attached := map[*libbpfgo.BPFProg]bool{}

	iter := module.Iterator()
	for {
		prog := iter.NextProgram()
		if prog == nil {
			break
		}

		span.AddEvent("prog_attach", trace.WithAttributes(attribute.String("SEC", prog.SectionName())))

		_, err := prog.AttachGeneric()
		if err != nil {
			log.Printf("Failed to attach program %q for config %q: %v", prog.Name(), cfg.Name, err)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			attached[prog] = false
		} else {
			attached[prog] = true
		}
	}

	return attached
}
