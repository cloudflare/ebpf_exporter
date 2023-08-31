package exporter

import "C"

import (
	"log"
	"syscall"
	"unsafe"
)

// These callbacks need to be in a separate file to avoid multiple definitions error

//export attachPerfEventCallback
func attachPerfEventCallback(prog unsafe.Pointer, _ C.long, link *unsafe.Pointer) C.int {
	program := (*C.struct_bpf_program)(prog)

	links, err := attachPerfEvent(program)
	if err != nil {
		log.Printf("Error attaching perf event: %v", err)
		return C.int(syscall.EINVAL)
	}

	// Use the first link as we need to return something
	*link = unsafe.Pointer(&links[0])

	return C.int(0)
}
