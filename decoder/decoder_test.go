package decoder

import (
	"fmt"
	"sync"
	"testing"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

func TestDecodeLabels(t *testing.T) {
	cases := []struct {
		in     []byte
		labels []config.Label
		out    []string
		err    bool
	}{
		{
			in: append([]byte{0x8, 0x0, 0x0, 0x0}, zeroPaddedString("potatoes", 16)...),
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
			in: append([]byte{0x8, 0x1, 0x1, 0x1}, zeroPaddedString("bananas", 32)...),
			labels: []config.Label{
				{
					Name:    "number",
					Size:    1,
					Padding: 3, // only first byte should be used  for the label
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
			err: true, // this label should be skipped, only tomatoes allowed
		},
	}

	for i, c := range cases {
		s, err := NewSet(nil)
		if err != nil {
			t.Fatal(err)
		}

		out, err := s.DecodeLabelsForMetrics(c.in, fmt.Sprintf("test:%d", i), c.labels)
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

func TestDecoderSetConcurrency(t *testing.T) {
	in := append([]byte{0x8, 0x0, 0x0, 0x0}, zeroPaddedString("bananas", 32)...)

	labels := []config.Label{
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
	}

	s, err := NewSet(nil)
	if err != nil {
		t.Fatal(err)
	}

	count := 1000

	wg := sync.WaitGroup{}
	wg.Add(count)

	for range count {
		go func() {
			defer wg.Done()

			_, err := s.DecodeLabelsForMetrics(in, "concurrency", labels)
			if err != nil {
				t.Error(err)
			}

			_, err = s.DecodeLabelsForTracing(in, labels)
			if err != nil {
				t.Error(err)
			}
		}()
	}

	wg.Wait()
}

func TestDecoderSetCache(t *testing.T) {
	in := []byte{0xba, 0xbe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef}

	one := []config.Label{
		{
			Name: "single_u64",
			Size: 8,
			Decoders: []config.Decoder{
				{
					Name: "uint",
				},
			},
		},
	}

	two := []config.Label{
		{
			Name: "u32_one",
			Size: 4,
			Decoders: []config.Decoder{
				{
					Name: "uint",
				},
			},
		},
		{
			Name: "u32_two",
			Size: 4,
			Decoders: []config.Decoder{
				{
					Name: "uint",
				},
			},
		},
	}

	s, err := NewSet(nil)
	if err != nil {
		t.Fatal(err)
	}

	single, err := s.DecodeLabelsForMetrics(in, "one", one)
	if err != nil {
		t.Fatal(err)
	}

	if len(single) != 1 {
		t.Errorf("Expected one u64 from %#v, got %#v", one, single)
	}

	double, err := s.DecodeLabelsForMetrics(in, "two", two)
	if err != nil {
		t.Error(err)
	}

	if len(double) != 2 {
		t.Errorf("Expected two u32 from %#v, got %#v", two, double)
	}
}

func BenchmarkCache(b *testing.B) {
	in := []byte{
		0x8, 0xab, 0xce, 0xef,
		0xde, 0xad,
		0xbe, 0xef,
		0x8, 0xab, 0xce, 0xef, 0x8, 0xab, 0xce, 0xef,
	}

	labels := []config.Label{
		{
			Name: "number1",
			Size: 4,
			Decoders: []config.Decoder{
				{
					Name: "uint",
				},
			},
		},
		{
			Name: "number2",
			Size: 2,
			Decoders: []config.Decoder{
				{
					Name: "uint",
				},
			},
		},
		{
			Name: "number3",
			Size: 2,
			Decoders: []config.Decoder{
				{
					Name: "uint",
				},
			},
		},
		{
			Name: "number4",
			Size: 8,
			Decoders: []config.Decoder{
				{
					Name: "uint",
				},
			},
		},
	}

	s, err := NewSet(nil)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("direct", func(b *testing.B) {
		for range b.N {
			_, err := s.decodeLabels(in, labels)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("cached", func(b *testing.B) {
		for range b.N {
			_, err := s.DecodeLabelsForMetrics(in, "test", labels)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func zeroPaddedString(in string, size int) []byte {
	if len(in) > size {
		panic(fmt.Sprintf("string %q is longer than requested size %d", in, size))
	}

	return append([]byte(in), make([]byte, size-len(in))...)
}
