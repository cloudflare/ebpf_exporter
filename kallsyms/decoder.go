package kallsyms

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Addr represents a ksym addr pair of a pointer and its symbol
type Addr struct {
	Ptr uintptr
	Sym string
}

// Decoder decodes ksym pointers to their symbols
type Decoder struct {
	mu    sync.Mutex
	path  string
	addrs []Addr
	found map[uintptr]string
}

// NewDecoder creates a new kallsyms decoder for a given kallsyms path (usually /proc/kallsyms)
func NewDecoder(path string) (*Decoder, error) {
	d := &Decoder{path: path, found: map[uintptr]string{}}

	err := d.refreshMapping()
	if err != nil {
		return nil, err
	}

	return d, nil
}

// refreshMapping re-reads kallsyms and rebuilds internal mapping
func (d *Decoder) refreshMapping() error {
	d.addrs = []Addr{}
	d.found = map[uintptr]string{}

	fd, err := os.Open(d.path)
	if err != nil {
		return fmt.Errorf("error opening kallsyms at %q: %v", d.path, err)
	}

	defer fd.Close()

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), " ")
		if len(parts) < 3 {
			continue
		}

		ptr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			return fmt.Errorf("error parsing kallsyms addr %q: %v", parts[0], err)
		}

		d.addrs = append(d.addrs, Addr{
			Ptr: uintptr(ptr),
			Sym: parts[2],
		})
	}

	err = scanner.Err()
	if err != nil {
		return fmt.Errorf("error scanning kallsyms from %q: %v", d.path, scanner.Err())
	}

	sort.Slice(d.addrs, func(i, j int) bool {
		return d.addrs[i].Ptr < d.addrs[j].Ptr
	})

	return nil
}

// findFirstBeforePtrLocked finds the the first addr that precedes the given pointer
func (d *Decoder) findFirstBeforePtrLocked(ptr uintptr) Addr {
	start := 0
	end := len(d.addrs) - 1
	mid := 0

	for {
		if start >= end {
			break
		}

		mid = start + (end-start+1)/2

		if d.addrs[mid].Ptr <= ptr {
			start = mid
		} else {
			end = mid - 1
		}
	}

	if start == end && d.addrs[start].Ptr <= ptr {
		return d.addrs[start]
	}

	return Addr{}
}

// fillStackLocked fills the given stack of pointers with the corresponding addresses
func (d *Decoder) fillStackLocked(stack []Addr) bool {
	filled := true

	for i := range stack {
		stack[i].Sym = d.findFirstBeforePtrLocked(stack[i].Ptr).Sym

		if stack[i].Sym == "" {
			filled = false
		}
	}

	return filled
}

// Stack returns the decoded stack for a given array of frame pointers
func (d *Decoder) Stack(addrs []uintptr) []Addr {
	d.mu.Lock()
	defer d.mu.Unlock()

	stack := make([]Addr, len(addrs))
	for i, ptr := range addrs {
		stack[i].Ptr = ptr
	}

	if !d.fillStackLocked(stack) {
		err := d.refreshMapping()
		if err != nil {
			panic(err)
		}

		d.fillStackLocked(stack)
	}

	return stack
}

// saveSymLocked resolves the kernel symbol at the given address
func (d *Decoder) saveSymLookupLocked(ptr uintptr) bool {
	addr := d.findFirstBeforePtrLocked(ptr)
	if addr.Ptr == ptr {
		d.found[ptr] = addr.Sym
		return true
	}

	return false
}

// Sym returns the kernel symbol at the given address
func (d *Decoder) Sym(ptr uintptr) string {
	d.mu.Lock()
	defer d.mu.Unlock()

	if found, ok := d.found[ptr]; ok {
		return found
	}

	if !d.saveSymLookupLocked(ptr) {
		err := d.refreshMapping()
		if err != nil {
			panic(err)
		}

		d.saveSymLookupLocked(ptr)
	}

	return d.found[ptr]
}
