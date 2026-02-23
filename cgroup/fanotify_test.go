package cgroup

import (
	"strings"
	"testing"
)

func TestParseMountinfoForPrefix(t *testing.T) {
	// Each line is one mountinfo record; field 4 (0-based) is the mount point. No leading whitespace.
	mockMountinfo := strings.Join([]string{
		"36 35 98:0 / /sys/fs/cgroup rw,nosuid,nodev,noexec - tmpfs tmpfs rw",
		"37 36 0:25 / /sys/fs/cgroup/unified rw - cgroup2 cgroup2 rw",
		"38 36 0:26 / /sys/fs/cgroup/systemd rw - cgroup cgroup rw,name=systemd",
		"39 36 0:27 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory",
		"40 36 0:28 / /sys/fs/cgroup/cpu,cpuacct rw - cgroup cgroup rw,cpu,cpuacct",
		"41 30 0:29 / /var/lib/docker/overlay2 rw - overlay overlay rw",
	}, "\n")

	testCases := []struct {
		name    string
		prefix  string
		want    []string
		wantErr bool
	}{
		{
			name:   "cgroup root returns all cgroup mounts",
			prefix: "/sys/fs/cgroup",
			want:   []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified", "/sys/fs/cgroup/systemd", "/sys/fs/cgroup/memory", "/sys/fs/cgroup/cpu,cpuacct"},
		},
		{
			name:   "subpath returns only under that path",
			prefix: "/sys/fs/cgroup/memory",
			want:   []string{"/sys/fs/cgroup/memory"},
		},
		{
			name:   "exact match single",
			prefix: "/var/lib/docker/overlay2",
			want:   []string{"/var/lib/docker/overlay2"},
		},
		{
			name:   "no match returns empty",
			prefix: "/nonexistent",
			want:   nil,
		},
		{
			name:   "prefix with trailing slash matches no paths (no mount has //)",
			prefix: "/sys/fs/cgroup/",
			want:   nil,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := parseMountinfoForPrefix(strings.NewReader(mockMountinfo), testCase.prefix)
			if (err != nil) != testCase.wantErr {
				t.Errorf("parseMountinfoForPrefix() error = %v, wantErr %v", err, testCase.wantErr)
				return
			}
			if len(got) != len(testCase.want) {
				t.Errorf("parseMountinfoForPrefix() len = %v, want %v (got %v)", len(got), len(testCase.want), got)
				return
			}
			for i := range got {
				if got[i] != testCase.want[i] {
					t.Errorf("parseMountinfoForPrefix() [%d] = %v, want %v", i, got[i], testCase.want[i])
				}
			}
		})
	}
}

func TestParseMountinfoForPrefix_skipsMalformed(t *testing.T) {
	// First line has no " - "; next two are malformed; only the last line is valid.
	mockMountinfo := strings.Join([]string{
		"36 35 98:0 / /sys/fs/cgroup rw",
		"no-dash-here",
		"1 2 3",
		"40 36 0:28 / /sys/fs/cgroup/ok rw - cgroup cgroup rw",
	}, "\n")

	got, err := parseMountinfoForPrefix(strings.NewReader(mockMountinfo), "/sys/fs/cgroup")
	if err != nil {
		t.Fatalf("parseMountinfoForPrefix() error = %v", err)
	}
	want := []string{"/sys/fs/cgroup/ok"}
	if len(got) != len(want) || (len(got) > 0 && got[0] != want[0]) {
		t.Errorf("parseMountinfoForPrefix() = %v, want %v (malformed lines should be skipped)", got, want)
	}
}
