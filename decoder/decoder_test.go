package decoder

import (
	"fmt"
	"testing"

	"github.com/cloudflare/ebpf_exporter/config"
)

func TestDecodeLabels(t *testing.T) {
	cases := []struct {
		in     []byte
		labels []config.Label
		out    []string
		err    bool
	}{
		{
			in: append([]byte{0x8, 0x0, 0x0, 0x0}, zeroPaddedString("bananas", 32)...),
			labels: []config.Label{
				{
					Name: "number",
					Size: 4,
					Decoders: []config.Decoder{
						{
							Name: "uint",
						},
					},
				},
			},
			out: []string{"8"},
			err: true, // not all labels are decoded
		},
		{
			in: append([]byte{0x8, 0x0, 0x0, 0x0}, zeroPaddedString("bananas", 32)...),
			labels: []config.Label{
				{
					Name: "number",
					Size: 4,
					Decoders: []config.Decoder{
						{
							Name: "uint",
						},
					},
				},
				{
					Name: "fruit",
					Size: 32,
					Decoders: []config.Decoder{
						{
							Name: "string",
						},
					},
				},
			},
			out: []string{"8", "bananas"},
			err: false,
		},
		{
			in: append([]byte{0x8, 0x0, 0x0, 0x0}, zeroPaddedString("bananas", 32)...),
			labels: []config.Label{
				{
					Name: "number",
					Size: 4,
					Decoders: []config.Decoder{
						{
							Name: "uint",
						},
					},
				},
				{
					Name: "fruit",
					Size: 32,
					Decoders: []config.Decoder{
						{
							Name: "string",
						},
						{
							Name: "regexp",
							Regexps: []string{
								"^bananas$",
								"$is-banana-even-fruit$",
							},
						},
					},
				},
			},
			out: []string{"8", "bananas"},
			err: false,
		},
		{
			in: append([]byte{0x8, 0x0, 0x0, 0x0}, zeroPaddedString("bananas", 32)...),
			labels: []config.Label{
				{
					Name: "number",
					Size: 4,
					Decoders: []config.Decoder{
						{
							Name: "uint",
						},
					},
				},
				{
					Name: "fruit",
					Size: 32,
					Decoders: []config.Decoder{
						{
							Name: "string",
						},
						{
							Name: "regexp",
							Regexps: []string{
								"^tomato$",
							},
						},
					},
				},
			},
			out: []string{"8", "bananas"},
			err: true, // this label should be skipped, only tomatos allowed
		},
	}

	for _, c := range cases {
		s := NewSet()

		out, err := s.DecodeLabels(c.in, c.labels)
		if c.err {
			if err == nil {
				t.Errorf("Expected error for input %#v and labels %#v, but did not receive it", c.in, c.labels)
			}

			continue
		}

		if err != nil {
			t.Errorf("Error decoding %#v with labels set to %#v: %s", c.in, c.labels, err)
		}

		if len(c.out) != len(out) {
			t.Errorf("Expected %d outputs (%v), received %d (%v)", len(c.out), c.out, len(out), out)
		}

		for i := 0; i < len(c.out) && i < len(out); i++ {
			if c.out[i] != out[i] {
				t.Errorf("Output label %d for input %#v is wrong: expected %s, but received %s", i, c.in, c.out[i], out[i])
			}
		}
	}
}

func zeroPaddedString(in string, size int) []byte {
	if len(in) > size {
		panic(fmt.Sprintf("string %q is longer than requested size %d", in, size))
	}

	return append([]byte(in), make([]byte, size-len(in))...)
}
