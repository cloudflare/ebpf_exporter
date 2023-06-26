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

func registerXDPHandler() error {
	name := C.CString("xdp/")
	defer C.free(unsafe.Pointer(name))

	opts := C.struct_libbpf_prog_handler_opts{}
	opts.sz = C.sizeof_struct_libbpf_prog_handler_opts
	opts.prog_attach_fn = C.libbpf_prog_attach_fn_t(C.attachXDPCallback)

	handler := C.libbpf_register_prog_handler(name, uint32(libbpfgo.BPFProgTypeXdp), uint32(libbpfgo.BPFAttachTypeXDP), &opts)
	if handler < 0 {
		return fmt.Errorf("error registering prog handler: %s", unix.ErrnoName(syscall.Errno(handler)))
	}

	libbpf_prog_handlers = append(libbpf_prog_handlers, int(handler))

	return nil
}

func attachXDP(prog *C.struct_bpf_program) ([]*C.struct_bpf_link, error) {
	name := C.GoString(C.bpf_program__name(prog))
	section := C.GoString(C.bpf_program__section_name(prog))
	devices := strings.Split(strings.TrimPrefix(section, "xdp/"), ",")
	links := make([]*C.struct_bpf_link, len(devices))

	cnt := 0
	for _, deviceName := range devices {
		iface, err := net.InterfaceByName(deviceName)
		if err != nil {
			fmt.Printf("failed to find device by name %s: %v\n", deviceName, err)
			continue
		}
		link, errno := C.bpf_program__attach_xdp(prog, C.int(iface.Index))
		if link == nil {
			fmt.Printf("failed to attach xdp on device %s to program %s: %v\n", deviceName, name, errno)
			continue
		}
		links[cnt] = link
		cnt++
	}
	return links, nil
}
