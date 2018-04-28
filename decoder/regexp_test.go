package decoder

import (
	"testing"

	"github.com/cloudflare/ebpf_exporter/config"
)

func TestRegexpDecode(t *testing.T) {
	for _, tc := range []struct {
		in     string
		regexp string
		v      string
		l      int
	}{
		{`journald testing`, `systemd-journald\b`, "", 0},
		{`journald testing`, `journald\b`, "journald", 8},
		{`hello testing`, `hel\w{2}\b`, "hello", 5},
	} {
		s := &Regexp{}
		out, lout, _ := s.Decode(tc.in, config.Decoder{
			Regexps: []string{tc.regexp},
		})
		if out != tc.v || lout != tc.l {
			t.Errorf("Expected %s(%d), got %s(%d)", tc.v, tc.l, out, lout)
		}
	}
}
