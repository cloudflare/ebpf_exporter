package decoder

import (
	"bytes"
	"os"
	"testing"

	"github.com/cloudflare/ebpf_exporter/v2/config"
	"github.com/cloudflare/ebpf_exporter/v2/kallsyms"
)

func TestKsymDecoder(t *testing.T) {
	cases := []struct {
		in  []byte
		out []byte
	}{
		{
			in:  []byte{0x28, 0x08, 0xd9, 0x19, 0xeb, 0xff, 0xff, 0xff},
			out: []byte("unknown_addr:0xffffffeb19d90828"),
		},
		{
			in:  []byte{0x30, 0x08, 0xd9, 0x19, 0xeb, 0xff, 0xff, 0xff},
			out: []byte("pipe_lock"),
		},
		{
			in:  []byte{0x70, 0x08, 0xd9, 0x19, 0xeb, 0xff, 0xff, 0xff},
			out: []byte("pipe_unlock"),
		},
		{
			in:  []byte{0x78, 0x08, 0xd9, 0x19, 0xeb, 0xff, 0xff, 0xff},
			out: []byte("unknown_addr:0xffffffeb19d90878"),
		},
	}

	fd, err := os.CreateTemp("", "kallsyms")
	if err != nil {
		t.Fatalf("Error creating temporary file for kallsyms: %v", err)
	}

	defer os.Remove(fd.Name())

	_, err = fd.WriteString("ffffffeb19d90830 T pipe_lock\nffffffeb19d90870 T pipe_unlock\n")
	if err != nil {
		t.Fatalf("Error writing fake kallsyms data to %q: %v", fd.Name(), err)
	}

	decoder, err := kallsyms.NewDecoder(fd.Name())
	if err != nil {
		t.Fatalf("Error creating ksym decoder for %q: %v", fd.Name(), err)
	}

	d := KSym{decoder}

	for _, c := range cases {
		out, err := d.Decode(c.in, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v: %s", c.in, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %q, got %q", c.out, out)
		}
	}
}
