// Copyright 2016 PLUMgrid
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bcc

import (
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
*/
import "C"

// Module type
type Module struct {
	p           unsafe.Pointer
	funcs       map[string]int
	kprobes     map[string]unsafe.Pointer
	uprobes     map[string]unsafe.Pointer
	tracepoints map[string]unsafe.Pointer
}

type compileRequest struct {
	code   string
	cflags []string
	rspCh  chan *Module
}

const (
	BPF_PROBE_ENTRY = iota
	BPF_PROBE_RETURN
)

var (
	defaultCflags []string
	compileCh     chan compileRequest
	bpfInitOnce   sync.Once
)

func bpfInit() {
	defaultCflags = []string{
		fmt.Sprintf("-DNUMCPUS=%d", runtime.NumCPU()),
	}
	compileCh = make(chan compileRequest)
	go compile()
}

// NewModule constructor
func newModule(code string, cflags []string) *Module {
	cflagsC := make([]*C.char, len(defaultCflags)+len(cflags))
	defer func() {
		for _, cflag := range cflagsC {
			C.free(unsafe.Pointer(cflag))
		}
	}()
	for i, cflag := range cflags {
		cflagsC[i] = C.CString(cflag)
	}
	for i, cflag := range defaultCflags {
		cflagsC[len(cflags)+i] = C.CString(cflag)
	}
	cs := C.CString(code)
	defer C.free(unsafe.Pointer(cs))
	c := C.bpf_module_create_c_from_string(cs, 2, (**C.char)(&cflagsC[0]), C.int(len(cflagsC)))
	if c == nil {
		return nil
	}
	return &Module{
		p:           c,
		funcs:       make(map[string]int),
		kprobes:     make(map[string]unsafe.Pointer),
		uprobes:     make(map[string]unsafe.Pointer),
		tracepoints: make(map[string]unsafe.Pointer),
	}
}

// NewModule asynchronously compiles the code, generates a new BPF
// module and returns it.
func NewModule(code string, cflags []string) *Module {
	bpfInitOnce.Do(bpfInit)
	ch := make(chan *Module)
	compileCh <- compileRequest{code, cflags, ch}
	return <-ch
}

func compile() {
	for {
		req := <-compileCh
		req.rspCh <- newModule(req.code, req.cflags)
	}
}

// Close takes care of closing all kprobes opened by this modules and
// destroys the underlying libbpf module.
func (bpf *Module) Close() {
	C.bpf_module_destroy(bpf.p)
	for k, v := range bpf.kprobes {
		C.perf_reader_free(v)
		evNameCS := C.CString(k)
		C.bpf_detach_kprobe(evNameCS)
		C.free(unsafe.Pointer(evNameCS))
	}
	for k, v := range bpf.uprobes {
		C.perf_reader_free(v)
		evNameCS := C.CString(k)
		C.bpf_detach_uprobe(evNameCS)
		C.free(unsafe.Pointer(evNameCS))
	}
	for k, v := range bpf.tracepoints {
		C.perf_reader_free(v)
		parts := strings.SplitN(k, ":", 2)
		tpCategoryCS := C.CString(parts[0])
		tpNameCS := C.CString(parts[1])
		C.bpf_detach_tracepoint(tpCategoryCS, tpNameCS)
		C.free(unsafe.Pointer(tpCategoryCS))
		C.free(unsafe.Pointer(tpNameCS))
	}
	for _, fd := range bpf.funcs {
		syscall.Close(fd)
	}
}

// LoadNet loads a program of type BPF_PROG_TYPE_SCHED_ACT.
func (bpf *Module) LoadNet(name string) (int, error) {
	return bpf.Load(name, C.BPF_PROG_TYPE_SCHED_ACT, 0, 0)
}

// LoadKprobe loads a program of type BPF_PROG_TYPE_KPROBE.
func (bpf *Module) LoadKprobe(name string) (int, error) {
	return bpf.Load(name, C.BPF_PROG_TYPE_KPROBE, 0, 0)
}

// LoadTracepoint loads a program of type BPF_PROG_TYPE_TRACEPOINT
func (bpf *Module) LoadTracepoint(name string) (int, error) {
	return bpf.Load(name, C.BPF_PROG_TYPE_TRACEPOINT, 0, 0)
}

// LoadUprobe loads a program of type BPF_PROG_TYPE_KPROBE.
func (bpf *Module) LoadUprobe(name string) (int, error) {
	return bpf.Load(name, C.BPF_PROG_TYPE_KPROBE, 0, 0)
}

// Load a program.
func (bpf *Module) Load(name string, progType int, logLevel, logSize uint) (int, error) {
	fd, ok := bpf.funcs[name]
	if ok {
		return fd, nil
	}
	fd, err := bpf.load(name, progType, logLevel, logSize)
	if err != nil {
		return -1, err
	}
	bpf.funcs[name] = fd
	return fd, nil
}

func (bpf *Module) load(name string, progType int, logLevel, logSize uint) (int, error) {
	nameCS := C.CString(name)
	defer C.free(unsafe.Pointer(nameCS))
	start := (*C.struct_bpf_insn)(C.bpf_function_start(bpf.p, nameCS))
	size := C.int(C.bpf_function_size(bpf.p, nameCS))
	license := C.bpf_module_license(bpf.p)
	version := C.bpf_module_kern_version(bpf.p)
	if start == nil {
		return -1, fmt.Errorf("Module: unable to find %s", name)
	}
	var logBuf []byte
	var logBufP *C.char
	if logSize > 0 {
		logBuf = make([]byte, logSize)
		logBufP = (*C.char)(unsafe.Pointer(&logBuf[0]))
	}
	fd, err := C.bpf_prog_load(uint32(progType), nameCS, start, size, license, version, C.int(logLevel), logBufP, C.uint(len(logBuf)))
	if fd < 0 {
		return -1, fmt.Errorf("error loading BPF program: %v", err)
	}
	return int(fd), nil
}

var kprobeRegexp = regexp.MustCompile("[+.]")
var uprobeRegexp = regexp.MustCompile("[^a-zA-Z0-9_]")

func (bpf *Module) attachProbe(evName string, attachType uint32, fnName string, fd int) error {
	if _, ok := bpf.kprobes[evName]; ok {
		return nil
	}

	evNameCS := C.CString(evName)
	fnNameCS := C.CString(fnName)
	res, err := C.bpf_attach_kprobe(C.int(fd), attachType, evNameCS, fnNameCS, -1, 0, -1, nil, nil)
	C.free(unsafe.Pointer(evNameCS))
	C.free(unsafe.Pointer(fnNameCS))

	if res == nil {
		return fmt.Errorf("failed to attach BPF kprobe: %v", err)
	}
	bpf.kprobes[evName] = res
	return nil
}

func (bpf *Module) attachUProbe(evName string, attachType uint32, path string, addr uint64, fd, pid int) error {
	evNameCS := C.CString(evName)
	binaryPathCS := C.CString(path)
	res, err := C.bpf_attach_uprobe(C.int(fd), attachType, evNameCS, binaryPathCS, (C.uint64_t)(addr), (C.pid_t)(pid), 0, -1, nil, nil)
	C.free(unsafe.Pointer(evNameCS))
	C.free(unsafe.Pointer(binaryPathCS))

	if res == nil {
		return fmt.Errorf("failed to attach BPF uprobe: %v", err)
	}
	bpf.uprobes[evName] = res
	return nil
}

// AttachKprobe attaches a kprobe fd to a function.
func (bpf *Module) AttachKprobe(fnName string, fd int) error {
	evName := "p_" + kprobeRegexp.ReplaceAllString(fnName, "_")

	return bpf.attachProbe(evName, BPF_PROBE_ENTRY, fnName, fd)
}

// AttachKretprobe attaches a kretprobe fd to a function.
func (bpf *Module) AttachKretprobe(fnName string, fd int) error {
	evName := "r_" + kprobeRegexp.ReplaceAllString(fnName, "_")

	return bpf.attachProbe(evName, BPF_PROBE_RETURN, fnName, fd)
}

// AttachTracepoint attaches a tracepoint fd to a function
// The 'name' argument is in the format 'category:name'
func (bpf *Module) AttachTracepoint(name string, fd int) error {
	if _, ok := bpf.tracepoints[name]; ok {
		return nil
	}

	parts := strings.SplitN(name, ":", 2)
	if len(parts) < 2 {
		return fmt.Errorf("failed to parse tracepoint name, expected %q, got %q", "category:name", name)
	}

	tpCategoryCS := C.CString(parts[0])
	tpNameCS := C.CString(parts[1])

	res, err := C.bpf_attach_tracepoint(C.int(fd), tpCategoryCS, tpNameCS, -1, 0, -1, nil, nil)

	C.free(unsafe.Pointer(tpCategoryCS))
	C.free(unsafe.Pointer(tpNameCS))

	if res == nil {
		return fmt.Errorf("failed to attach BPF tracepoint: %v", err)
	}
	bpf.tracepoints[name] = res
	return nil
}

// AttachUprobe attaches a uprobe fd to the symbol in the library or binary 'name'
// The 'name' argument can be given as either a full library path (/usr/lib/..),
// a library without the lib prefix, or as a binary with full path (/bin/bash)
// A pid can be given to attach to, or -1 to attach to all processes
//
// Presently attempts to trace processes running in a different namespace
// to the tracer will fail due to limitations around namespace-switching
// in multi-threaded programs (such as Go programs)
func (bpf *Module) AttachUprobe(name, symbol string, fd, pid int) error {
	path, addr, err := resolveSymbolPath(name, symbol, 0x0, pid)
	if err != nil {
		return err
	}
	evName := fmt.Sprintf("p_%s_0x%x", uprobeRegexp.ReplaceAllString(path, "_"), addr)
	return bpf.attachUProbe(evName, BPF_PROBE_ENTRY, path, addr, fd, pid)
}

// AttachMatchingUprobes attaches a uprobe fd to all symbols in the library or binary
// 'name' that match a given pattern.
// The 'name' argument can be given as either a full library path (/usr/lib/..),
// a library without the lib prefix, or as a binary with full path (/bin/bash)
// A pid can be given, or -1 to attach to all processes
//
// Presently attempts to trace processes running in a different namespace
// to the tracer will fail due to limitations around namespace-switching
// in multi-threaded programs (such as Go programs)
func (bpf *Module) AttachMatchingUprobes(name, match string, fd, pid int) error {
	symbols, err := matchUserSymbols(name, match)
	if err != nil {
		return fmt.Errorf("unable to match symbols: %s", err)
	}
	if len(symbols) == 0 {
		return fmt.Errorf("no symbols matching %s for %s found", match, name)
	}
	for _, symbol := range symbols {
		if err := bpf.AttachUprobe(name, symbol.name, fd, pid); err != nil {
			return err
		}
	}
	return nil
}

// AttachUretprobe attaches a uretprobe fd to the symbol in the library or binary 'name'
// The 'name' argument can be given as either a full library path (/usr/lib/..),
// a library without the lib prefix, or as a binary with full path (/bin/bash)
// A pid can be given to attach to, or -1 to attach to all processes
//
// Presently attempts to trace processes running in a different namespace
// to the tracer will fail due to limitations around namespace-switching
// in multi-threaded programs (such as Go programs)
func (bpf *Module) AttachUretprobe(name, symbol string, fd, pid int) error {
	path, addr, err := resolveSymbolPath(name, symbol, 0x0, pid)
	if err != nil {
		return err
	}
	evName := fmt.Sprintf("r_%s_0x%x", uprobeRegexp.ReplaceAllString(path, "_"), addr)
	return bpf.attachUProbe(evName, BPF_PROBE_RETURN, path, addr, fd, pid)
}

// AttachMatchingUretprobes attaches a uretprobe fd to all symbols in the library or binary
// 'name' that match a given pattern.
// The 'name' argument can be given as either a full library path (/usr/lib/..),
// a library without the lib prefix, or as a binary with full path (/bin/bash)
// A pid can be given, or -1 to attach to all processes
//
// Presently attempts to trace processes running in a different namespace
// to the tracer will fail due to limitations around namespace-switching
// in multi-threaded programs (such as Go programs)
func (bpf *Module) AttachMatchingUretprobes(name, match string, fd, pid int) error {
	symbols, err := matchUserSymbols(name, match)
	if err != nil {
		return fmt.Errorf("unable to match symbols: %s", err)
	}
	if len(symbols) == 0 {
		return fmt.Errorf("no symbols matching %s for %s found", match, name)
	}
	for _, symbol := range symbols {
		if err := bpf.AttachUretprobe(name, symbol.name, fd, pid); err != nil {
			return err
		}
	}
	return nil
}

// TableSize returns the number of tables in the module.
func (bpf *Module) TableSize() uint64 {
	size := C.bpf_num_tables(bpf.p)
	return uint64(size)
}

// TableId returns the id of a table.
func (bpf *Module) TableId(name string) C.size_t {
	cs := C.CString(name)
	defer C.free(unsafe.Pointer(cs))
	return C.bpf_table_id(bpf.p, cs)
}

// TableDesc returns a map with table properties (name, fd, ...).
func (bpf *Module) TableDesc(id uint64) map[string]interface{} {
	i := C.size_t(id)
	return map[string]interface{}{
		"name":      C.GoString(C.bpf_table_name(bpf.p, i)),
		"fd":        int(C.bpf_table_fd_id(bpf.p, i)),
		"key_size":  uint64(C.bpf_table_key_size_id(bpf.p, i)),
		"leaf_size": uint64(C.bpf_table_leaf_size_id(bpf.p, i)),
		"key_desc":  C.GoString(C.bpf_table_key_desc_id(bpf.p, i)),
		"leaf_desc": C.GoString(C.bpf_table_leaf_desc_id(bpf.p, i)),
	}
}

// TableIter returns a receveier channel to iterate over entries.
func (bpf *Module) TableIter() <-chan map[string]interface{} {
	ch := make(chan map[string]interface{})
	go func() {
		size := C.bpf_num_tables(bpf.p)
		for i := C.size_t(0); i < size; i++ {
			ch <- bpf.TableDesc(uint64(i))
		}
		close(ch)
	}()
	return ch
}

func (bpf *Module) attachXDP(devName string, fd int, flags uint32) error {
	devNameCS := C.CString(devName)
	res, err := C.bpf_attach_xdp(devNameCS, C.int(fd), C.uint32_t(flags))
	defer C.free(unsafe.Pointer(devNameCS))

	if res != 0 || err != nil {
		return fmt.Errorf("failed to attach BPF xdp to device %v: %v", devName, err)
	}
	return nil
}

// AttachXDP attaches a xdp fd to a device.
func (bpf *Module) AttachXDP(devName string, fd int) error {
	return bpf.attachXDP(devName, fd, 0)
}

// RemoveXDP removes any xdp from this device.
func (bpf *Module) RemoveXDP(devName string) error {
	return bpf.attachXDP(devName, -1, 0)
}
