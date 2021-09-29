package decoder

import (
	"bytes"
	"testing"

	"github.com/cloudflare/ebpf_exporter/config"
)

func TestCgroupDecoder(t *testing.T) {
	cases := []struct {
		in    []byte
		cache map[uint64][]byte
		out   []byte
	}{
		{
			in:    []byte("6"),
			cache: map[uint64][]byte{uint64(6): []byte("cgroup_six")},
			out:   []byte("cgroup_six"),
		},
		{
			in:    []byte("6"),
			cache: map[uint64][]byte{uint64(7): []byte("cgroup_seven")},
			out:   []byte("unknown_cgroup_id:6"),
		},
	}

	for _, c := range cases {
		d := &CGroup{cache: c.cache}

		out, err := d.Decode(c.in, config.Decoder{})
		if err != nil {
			t.Errorf("Error decoding %#v with cache set to %#v: %s", c.in, c.cache, err)
		}

		if !bytes.Equal(out, c.out) {
			t.Errorf("Expected %s, got %s", c.out, out)
		}
	}
}

func BenchmarkCgroupRefresh(b *testing.B) {
	d := &CGroup{cache: map[uint64][]byte{}}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := d.refreshCache()
		if err != nil {
			b.Errorf("Failed to refresh cgroup cache: %s", err)
		}
	}
}
