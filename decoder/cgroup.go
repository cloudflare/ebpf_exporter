package decoder

import (
	"fmt"
	"strconv"

	"github.com/cloudflare/ebpf_exporter/v2/cgroup"
	"github.com/cloudflare/ebpf_exporter/v2/config"
)

// CGroup is a decoder that transforms cgroup id to path in cgroupfs
type CGroup struct {
	monitor *cgroup.Monitor
}

// NewCgroupDecoder creates a new cgroup decoder
func NewCgroupDecoder() (*CGroup, error) {
	monitor, err := cgroup.NewMonitor("/sys/fs/cgroup")
	if err != nil {
		return nil, fmt.Errorf("error creating cgroup monitor: %v", err)
	}

	return &CGroup{monitor}, nil
}

// Decode transforms cgroup id to path in cgroupfs
func (c *CGroup) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	cgroupID, err := strconv.Atoi(string(in))
	if err != nil {
		return nil, err
	}

	path := c.monitor.Resolve(cgroupID)

	if path == "" {
		path = fmt.Sprintf("unknown_cgroup_id:%d", cgroupID)
	}

	return []byte(path), nil
}
