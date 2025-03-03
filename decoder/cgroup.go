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
