package decoder

import (
	"testing"

	"github.com/cloudflare/ebpf_exporter/config"
)

func TestStaticMapDecode(t *testing.T) {
	for _, tc := range []struct {
		in string
		v  string
		l  int
	}{
		{`0x2 testing`, "slow", 3},
	} {
		s := &StaticMap{}
		out, lout, err := s.Decode(tc.in, config.Decoder{
			StaticMap: map[string]string{"0x1": "refs", "0x2": "slow", "0x3": "miss"},
		})
		if err != nil {
			t.Error(err)
		}
		if out != tc.v || lout != tc.l {
			t.Errorf("Expected %s(%d), got %s(%d)", tc.v, tc.l, out, lout)
		}
	}
}
