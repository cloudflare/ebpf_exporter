package exporter

import (
	"fmt"
	"regexp"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/v2/cgroup"
	"github.com/cloudflare/ebpf_exporter/v2/config"
)

type CgroupIdMap struct {
	bpfMap *libbpfgo.BPFMap
	ch     chan cgroup.CgroupChange
	cache  map[string]*regexp.Regexp
}

func newCgroupIdMap(module *libbpfgo.Module, cfg config.Config) (*CgroupIdMap, error) {
	m, err := module.GetMap(cfg.CgroupIdMap.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get map %q: %w", cfg.CgroupIdMap.Name, err)
	}

	keySize := m.KeySize()
	if keySize != 8 {
		return nil, fmt.Errorf("key size for map %q is not expected 8 bytes (u64), it is %d bytes", cfg.CgroupIdMap.Name, keySize)
	}
	valueSize := m.ValueSize()
	if valueSize != 8 {
		return nil, fmt.Errorf("value size for map %q is not expected 8 bytes (u64), it is %d bytes", cfg.CgroupIdMap.Name, valueSize)
	}

	c := &CgroupIdMap{
		bpfMap: m,
		ch:     make(chan cgroup.CgroupChange, 10),
		cache:  map[string]*regexp.Regexp{},
	}

	for _, expr := range cfg.CgroupIdMap.Regexps {
		if _, ok := c.cache[expr]; !ok {
			compiled, err := regexp.Compile(expr)
			if err != nil {
				return nil, fmt.Errorf("error compiling regexp %q: %w", expr, err)
			}
			c.cache[expr] = compiled
		}
	}

	return c, nil
}

func (c *CgroupIdMap) subscribe(m *cgroup.Monitor) error {
	return m.SubscribeCgroupChange(c.ch)
}

func (c *CgroupIdMap) runLoop() {
	for update := range c.ch {
		if update.Remove {
			key := uint64(update.Id)
			c.bpfMap.DeleteKey(unsafe.Pointer(&key))
		} else {
			key := uint64(update.Id)
			value := uint64(1)
			if c.checkMatch(update.Path) {
				c.bpfMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&value))
			}
		}
	}
}

func (c *CgroupIdMap) checkMatch(path string) bool {
	for _, compiled := range c.cache {
		if compiled.MatchString(path) {
			return true
		}
	}
	return false
}
