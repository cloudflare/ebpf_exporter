package cgroup

import (
	"fmt"
	"os"
	"syscall"
)

func inode(path string) (int, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("error running stat(%q): %v", path, err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("missing syscall.Stat_t in FileInfo for %q", path)
	}

	return int(stat.Ino), nil
}
