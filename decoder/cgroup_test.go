package decoder

import (
	"testing"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

type fakeResolver map[int]string

func (f fakeResolver) Resolve(id int) string { return f[id] }

func TestCGroupDecode(t *testing.T) {
	d := &CGroup{monitor: fakeResolver{1: "/sys/fs/cgroup/a"}}

	cases := []struct {
		name string
		in   string
		cfg  config.Decoder
		out  string
	}{
		{"known", "1", config.Decoder{}, "/sys/fs/cgroup/a"},
		{"known with collapse", "1", config.Decoder{CollapseUnknown: true}, "/sys/fs/cgroup/a"},
		{"unknown keeps id by default", "2", config.Decoder{}, "unknown_cgroup_id:2"},
		{"unknown collapsed", "2", config.Decoder{CollapseUnknown: true}, "unknown_cgroup"},
		{"another unknown collapsed", "3", config.Decoder{CollapseUnknown: true}, "unknown_cgroup"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := d.Decode([]byte(c.in), c.cfg)
			if err != nil {
				t.Fatal(err)
			}

			if string(out) != c.out {
				t.Errorf("expected %q, got %q", c.out, out)
			}
		})
	}
}
