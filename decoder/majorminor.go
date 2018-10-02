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
	"github.com/iovisor/gobpf/bcc"
	"golang.org/x/sys/unix"
)

const (
	partitions = "/proc/partitions"
)

// MajorMinor is a decoder that transforms minormajor device id into name
type MajorMinor struct {
	cache map[uint64][]byte
}

// Decode transforms minormajor device id into device name like sda2
func (m *MajorMinor) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	if m.cache == nil {
		m.cache = map[uint64][]byte{}
	}

	// We only care about 4 bytes of a field that's stored as u32
	num := uint64(bcc.GetHostByteOrder().Uint32(in[0:4]))

	if _, ok := m.cache[num]; !ok {
		fd, err := os.Open(partitions)
		if err != nil {
			return nil, err
		}
		defer func() {
			// This never happened
			if err = fd.Close(); err != nil {
				log.Printf("Error closing %s: %s", partitions, err)
			}
		}()

		major := unix.Major(num)
		minor := unix.Minor(num)

		name := []byte(majorMinorToName(major, minor, fd))

		if len(name) == 0 {
			return []byte(fmt.Sprintf("unknown:%d:%d", major, minor)), nil
		}

		m.cache[num] = name
	}

	return m.cache[num], nil
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
