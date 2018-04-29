package decoder

import (
	"testing"

	"github.com/cloudflare/ebpf_exporter/config"
)

func TestUInt64Decode(t *testing.T) {
	for _, tc := range []struct {
		in string
		v  string
		l  int
	}{
		{`0x2 testing`, "2", 3},
		{`2 hello"`, "2", 1},
	} {
		s := &UInt64{}
		out, lout, err := s.Decode(tc.in, config.Decoder{})
		if err != nil {
			t.Error(err)
		}
		if out != tc.v || lout != tc.l {
			t.Errorf("Expected %s(%d), got %s(%d)", tc.v, tc.l, out, lout)
		}
	}
}
