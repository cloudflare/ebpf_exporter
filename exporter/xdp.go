package exporter

/*
#include <stdlib.h>
#include <bpf/libbpf.h>

extern int attachXDPCallback(const struct bpf_program *prog,
                                   long cookie,
                                   struct bpf_link **link);
*/
import "C"

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"golang.org/x/sys/unix"
)

var libbpfXDPHandlers []int

func registerXDPHandler() error {
	if libbpfXDPHandlers != nil {
		return nil
	}

	name := C.CString("xdp/")
	defer C.free(unsafe.Pointer(name))

	opts := C.struct_libbpf_prog_handler_opts{}
	opts.sz = C.sizeof_struct_libbpf_prog_handler_opts
	opts.prog_attach_fn = C.libbpf_prog_attach_fn_t(C.attachXDPCallback)

	handler := C.libbpf_register_prog_handler(name, uint32(libbpfgo.BPFProgTypeXdp), uint32(libbpfgo.BPFAttachTypeXDP), &opts)
	if handler < 0 {
		return fmt.Errorf("error registering prog handler: %s", unix.ErrnoName(syscall.Errno(handler)))
	}

	libbpfXDPHandlers = append(libbpfXDPHandlers, int(handler))

	return nil
}

func attachXDP(prog *C.struct_bpf_program) ([]*C.struct_bpf_link, error) {
	name := C.GoString(C.bpf_program__name(prog))
	section := C.GoString(C.bpf_program__section_name(prog))
	device := strings.TrimPrefix(section, "xdp/")

	iface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, fmt.Errorf("failed to find device %q for program %q: %v", device, name, err)
	}

	link, err := C.bpf_program__attach_xdp(prog, C.int(iface.Index))
	if link == nil {
		return nil, fmt.Errorf("failed to attach xdp on device %q for program %s: %v", device, name, err)
	}

	return []*C.struct_bpf_link{link}, nil
}
