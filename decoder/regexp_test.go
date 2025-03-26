package decoder

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

func TestRegexpDecoder(t *testing.T) {
	cases := []struct {
		in      []byte
		regexps []string
		out     []byte
		err     error
	}{
		{
			in:      []byte("systemd-journal"),
			regexps: []string{"^systemd-journal$", "^syslog-ng$"},
			out:     []byte("systemd-journal"),
			err:     nil,
		},
		{
			in:      []byte("syslog-ng"),
			regexps: []string{"^systemd-journal$", "^syslog-ng$"},
			out:     []byte("syslog-ng"),
			err:     nil,
		},
		{
			in:      []byte("systemd-bananad"),
			regexps: []string{"^systemd-journal$", "^syslog-ng$"},
			out:     []byte(""),
			err:     ErrSkipLabelSet,
		},
		{
			in:      []byte("systemd-bananad"),
			regexps: []string{"^(systemd).*$", "^syslog-ng$"},
			out:     []byte("systemd"),
			err:     nil,
		},
	}

	for _, c := range cases {
		d := &Regexp{}

		out, err := d.Decode(c.in, config.Decoder{Regexps: c.regexps})
		if !errors.Is(err, c.err) {
			t.Errorf("Error decoding %s (expected err = %v): %v", c.in, c.err, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %s, got %s", c.out, out)
		}
	}
}

func TestRegexpDecoderWithSkipCache(t *testing.T) {
	d := &Regexp{}
	input := []byte("whatever")
	_, err := d.Decode(input, config.Decoder{Regexps: []string{"^(systemd).*$", "^syslog-ng$"}, SkipCacheSize: 100})
	if !errors.Is(err, ErrSkipLabelSet) {
		t.Errorf("Error decoding %s: %v", input, err)
	}
	if !d.skipCache.Contains("whatever") {
		t.Errorf("failed to add to skipcache %s: kets=%v", input, d.skipCache.Keys())
	}
}
