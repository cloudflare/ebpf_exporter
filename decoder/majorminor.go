package decoder

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/cloudflare/ebpf_exporter/config"
	"golang.org/x/sys/unix"
)

// MajorMinor is a decoder that transforms minormajor device id into name
type MajorMinor struct {
	cache map[string]string
}

// Decode transforms minormajor device id into name
func (m *MajorMinor) Decode(in string, conf config.Decoder) (string, error) {
	if m.cache == nil {
		m.cache = map[string]string{}
	}

	num, err := strconv.ParseUint(in, 0, 64)
	if err != nil {
		return fmt.Sprintf("invalid:%s", in), err
	}

	if _, ok := m.cache[in]; !ok {
		fd, err := os.Open("/proc/partitions")
		if err != nil {
			return "", err
		}
		defer func() {
			// This never happened
			if err = fd.Close(); err != nil {
				log.Printf("Error closing %s: %s", kallsyms, err)
			}
		}()

		name := majorMinorToName(unix.Major(num), unix.Minor(num), fd)

		if name == "" {
			return fmt.Sprintf("unknown:%s", in), nil
		}

		m.cache[in] = name
	}

	return m.cache[in], nil
}

// majorMinorToName converts result of "new_encode_dev(dev_t dev)"
// in the kernel into device name like sda
func majorMinorToName(major, minor uint32, r io.Reader) string {
	majorString := strconv.Itoa(int(major))
	minorString := strconv.Itoa(int(minor))

	s := bufio.NewScanner(r)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) != 4 {
			continue
		}

		if fields[0] == majorString && fields[1] == minorString {
			return fields[3]
		}
	}

	return ""
}
