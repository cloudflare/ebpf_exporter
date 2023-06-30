package exporter

/*
#include <stdlib.h>
#include <bpf/libbpf.h>

extern int attachPerfEventCallback(const struct bpf_program *prog,
                                   long cookie,
                                   struct bpf_link **link);
*/
import "C"

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/elastic/go-perf"
	"github.com/iovisor/gobpf/pkg/cpuonline"
	"golang.org/x/sys/unix"
)

var libbpfPerfHandlers []int

func registerHandlers() error {
	if libbpfPerfHandlers != nil {
		return nil
	}

	name := C.CString("perf_event/")
	defer C.free(unsafe.Pointer(name))

	opts := C.struct_libbpf_prog_handler_opts{}
	opts.sz = C.sizeof_struct_libbpf_prog_handler_opts
	opts.prog_attach_fn = C.libbpf_prog_attach_fn_t(C.attachPerfEventCallback)

	handler := C.libbpf_register_prog_handler(name, uint32(libbpfgo.BPFProgTypePerfEvent), uint32(libbpfgo.BPFAttachTypePerfEvent), &opts)
	if handler < 0 {
		return fmt.Errorf("error registering prog handler: %s", unix.ErrnoName(syscall.Errno(handler)))
	}

	libbpfPerfHandlers = append(libbpfPerfHandlers, int(handler))

	return nil
}

func parseSectionConfig(section string) (*perf.Attr, []uint, error) {
	attr := &perf.Attr{}

	for _, item := range strings.Split(strings.TrimPrefix(section, "perf_event/"), ",") {
		kv := strings.SplitN(item, "=", 2)
		if len(kv) != 2 {
			return nil, nil, fmt.Errorf("invalid perf_event item: %q", item)
		}

		value, err := strconv.Atoi(kv[1])
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing value of item %q as integer: %v", item, err)
		}

		switch kv[0] {
		case "type":
			attr.Type = perf.EventType(value)
		case "config":
			attr.Config = uint64(value)
		case "frequency":
			attr.SetSampleFreq(uint64(value))
		default:
			return nil, nil, fmt.Errorf("unknown perf_event item %q", item)
		}
	}

	cpus, err := cpuonline.Get()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to determine online cpus: %v", err)
	}

	return attr, cpus, nil
}

func attachPerfEvent(prog *C.struct_bpf_program) ([]*C.struct_bpf_link, error) {
	section := C.GoString(C.bpf_program__section_name(prog))

	fa, cpus, err := parseSectionConfig(section)
	if err != nil {
		return nil, fmt.Errorf("failed to parse section %q: %v", section, err)
	}

	links := make([]*C.struct_bpf_link, len(cpus))

	name := C.GoString(C.bpf_program__name(prog))

	for i, cpu := range cpus {
		event, err := perf.Open(fa, perf.AllThreads, int(cpu), nil)
		if err != nil {
			return nil, fmt.Errorf("failed to open perf_event: %v", err)
		}

		fd, err := event.FD()
		if err != nil {
			return nil, fmt.Errorf("failed to get perf_event fd: %v", err)
		}

		link, err := C.bpf_program__attach_perf_event(prog, C.int(fd))
		if link == nil {
			return nil, fmt.Errorf("failed to attach perf event %d:%d to program %q on cpu %d: %v", fa.Type, fa.Config, name, cpu, err)
		}

		links[i] = link
	}

	return links, nil
}
