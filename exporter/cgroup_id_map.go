package exporter

import (
	"fmt"
	"log"
	"regexp"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/v2/cgroup"
	"github.com/cloudflare/ebpf_exporter/v2/config"
)

// CgroupIDMap synchronises cgroup changes with the shared bpf map.
type CgroupIDMap struct {
	bpfMap *libbpfgo.BPFMap
	ch     chan cgroup.ChangeNotification
	cache  map[string]*regexp.Regexp
}

func newCgroupIDMap(module *libbpfgo.Module, cfg config.Config) (*CgroupIDMap, error) {
	m, err := module.GetMap(cfg.CgroupIDMap.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get map %q: %w", cfg.CgroupIDMap.Name, err)
	}

	keySize := m.KeySize()
	if keySize != 8 {
		return nil, fmt.Errorf("key size for map %q is not expected 8 bytes (u64), it is %d bytes", cfg.CgroupIDMap.Name, keySize)
	}
	valueSize := m.ValueSize()
	if valueSize != 8 {
		return nil, fmt.Errorf("value size for map %q is not expected 8 bytes (u64), it is %d bytes", cfg.CgroupIDMap.Name, valueSize)
	}

	c := &CgroupIDMap{
		bpfMap: m,
		ch:     make(chan cgroup.ChangeNotification, 10),
		cache:  map[string]*regexp.Regexp{},
	}

	for _, expr := range cfg.CgroupIDMap.Regexps {
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

func (c *CgroupIDMap) subscribe(m *cgroup.Monitor) error {
	return m.SubscribeCgroupChange(c.ch)
}

func (c *CgroupIDMap) runLoop() {
	for update := range c.ch {
		if update.Remove {
			key := uint64(update.ID)
			err := c.bpfMap.DeleteKey(unsafe.Pointer(&key))
			log.Printf("Error deleting key from CgroupIDMap: %v", err)
		} else {
			key := uint64(update.ID)
			value := uint64(1)
			if c.checkMatch(update.Path) {
				err := c.bpfMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&value))
				log.Printf("Error updating CgroupIDMap: %v", err)
			}
		}
	}
}

func (c *CgroupIDMap) checkMatch(path string) bool {
	for _, compiled := range c.cache {
		if compiled.MatchString(path) {
			return true
		}
	}
	return false
}
