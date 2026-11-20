package decoder

import (
	"fmt"
	"strconv"

	"github.com/cloudflare/ebpf_exporter/v2/config"
)

// cgroupResolver resolves cgroup ids to paths, implemented by *cgroup.Monitor
type cgroupResolver interface {
	Resolve(id int) string
}

// CGroup is a decoder that transforms cgroup id to path in cgroupfs
type CGroup struct {
	monitor cgroupResolver
}

// Decode transforms cgroup id to path in cgroupfs
func (c *CGroup) Decode(in []byte, decoder config.Decoder) ([]byte, error) {
	cgroupID, err := strconv.Atoi(string(in))
	if err != nil {
		return nil, err
	}

	path := c.monitor.Resolve(cgroupID)

	if path == "" {
		if decoder.CollapseUnknown {
			path = "unknown_cgroup"
		} else {
			path = fmt.Sprintf("unknown_cgroup_id:%d", cgroupID)
		}
	}

	return []byte(path), nil
}
