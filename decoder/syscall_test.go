package decoder

import (
	"bytes"
	"runtime"
	"strconv"
	"testing"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

type syscallTestCase struct {
	in  []byte
	out []byte
}

func TestSyscallDecoder(t *testing.T) {
	cases := []syscallTestCase{}

	arm64 := map[int]string{
		0:   "io_setup",
		1:   "io_destroy",
		293: "rseq",
		447: "memfd_secret",
	}

	amd64 := map[int]string{
		0:   "read",
		1:   "write",
		293: "pipe2",
		447: "memfd_secret",
	}

	var arch map[int]string

	switch runtime.GOARCH {
	case "arm64":
		arch = arm64
	case "amd64":
		arch = amd64
	default:
		t.Errorf("unsupported architecture: %q", runtime.GOARCH)
	}

	for number, name := range arch {
		cases = append(cases, syscallTestCase{[]byte(strconv.Itoa(number)), []byte(name)})
	}

	for _, c := range cases {
		d := &Syscall{}

		out, err := d.Decode(c.in, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v to %#v: %s", c.in, c.out, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %s, got %s", c.out, out)
		}
	}
}
