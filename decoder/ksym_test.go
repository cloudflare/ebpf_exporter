package decoder

import (
	"testing"

	"github.com/cloudflare/ebpf_exporter/config"
)

func TestKsymDecode(t *testing.T) {
	for _, tc := range []struct {
		in string
		v  string
		l  int
	}{
		{`0x2 testing`, "hello", 3},
	} {
		s := &KSym{
			cache: map[string]string{"1": "hello"},
		}
		out, lout, _ := s.Decode(tc.in, config.Decoder{})
		if out != tc.v || lout != tc.l {
			t.Errorf("Expected %s(%d), got %s(%d)", tc.v, tc.l, out, lout)
		}
	}
}
