package decoder

import (
	"bufio"
	"errors"
	"io"
	"log"
	"os"
	"strings"
)

// TODO: Switch to https://github.com/iovisor/gobpf/pull/114 when merged

const (
	kallsyms = "/proc/kallsyms"
)

// Ksym translates a kernel memory address into a kernel function name
// using `/proc/kallsyms`
func Ksym(addr string) (string, error) {
	fd, err := os.Open(kallsyms)
	if err != nil {
		return "", err
	}
	defer func() {
		// This never happened
		if err = fd.Close(); err != nil {
			log.Printf("Error closing %s: %s", kallsyms, err)
		}
	}()

	fn := ksym(addr, fd)

	if fn == "" {
		return "", errors.New("kernel function not found for " + addr)
	}

	return fn, nil
}

func ksym(addr string, r io.Reader) string {
	s := bufio.NewScanner(r)
	for s.Scan() {
		l := s.Text()
		ar := strings.Split(l, " ")
		if len(ar) != 3 {
			continue
		}

		if ar[0] == addr {
			return ar[2]
		}
	}

	return ""
}
