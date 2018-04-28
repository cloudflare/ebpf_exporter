package decoder

import (
	"testing"

	"github.com/cloudflare/ebpf_exporter/config"
)

func TestStringDecode(t *testing.T) {
	for _, tc := range []struct {
		in string
		v  string
		l  int
	}{
		{`"hello" testing`, "hello", 6},
		{`"hello"`, "hello", 6},
		{`hello`, "hello", 5},
		{`hello world`, "hello world", 11},
	} {
		s := &String{}
		out, lout, err := s.Decode(tc.in, config.Decoder{})
		if err != nil {
			t.Error(err)
		}
		if out != tc.v || lout != tc.l {
			t.Errorf("Expected %s(%d), got %s(%d)", tc.v, tc.l, out, lout)
		}
	}
}
