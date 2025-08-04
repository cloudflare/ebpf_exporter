package exporter

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"regexp"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/v2/cgroup"
	"github.com/cloudflare/ebpf_exporter/v2/config"
)

// CgroupIDMap synchronises cgroup changes with the shared bpf map.
type CgroupIDMap struct {
	bpfMap     *libbpfgo.BPFMap
	bpfMapType config.CgroupIDMapType
	ch         chan cgroup.ChangeNotification
	cache      map[string]*regexp.Regexp
}

func newCgroupIDMap(module *libbpfgo.Module, cfg config.Config) (*CgroupIDMap, error) {
	m, err := module.GetMap(cfg.CgroupIDMap.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get map %q: %w", cfg.CgroupIDMap.Name, err)
	}

	keySize := m.KeySize()
	var expectedKeySize int
	switch cfg.CgroupIDMap.Type {
	case config.CgroupIDMapHashType:
		expectedKeySize = 8
	case config.CgroupIDMapCgrpStorageType:
		expectedKeySize = 4
	}
	if keySize != expectedKeySize {
		return nil, fmt.Errorf("key size for map %q is not expected %d bytes for map type %s, it is %d bytes", cfg.CgroupIDMap.Name, expectedKeySize, cfg.CgroupIDMap.Type, keySize)
	}
	valueSize := m.ValueSize()
	if valueSize != 8 {
		return nil, fmt.Errorf("value size for map %q is not expected 8 bytes (u64), it is %d bytes", cfg.CgroupIDMap.Name, valueSize)
	}

	c := &CgroupIDMap{
		bpfMap:     m,
		bpfMapType: cfg.CgroupIDMap.Type,
		ch:         make(chan cgroup.ChangeNotification, 10),
		cache:      map[string]*regexp.Regexp{},
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
			err := c.removeCgroup(uint64(update.ID))
			if err != nil {
				log.Printf("Error deleting key from CgroupIDMap %s: %v", c.bpfMap.Name(), err)
			}
		} else {
			err := c.updateCgroup(uint64(update.ID), update.Path)
			if err != nil {
				log.Printf("Error updating CgroupIDMap: %v", err)
			}
		}
	}
}

func (c *CgroupIDMap) removeCgroup(id uint64) error {
	// we only need to delete cgroup id for normal hash map
	if c.bpfMapType == config.CgroupIDMapCgrpStorageType {
		return nil
	}
	err := c.bpfMap.DeleteKey(unsafe.Pointer(&id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (c *CgroupIDMap) updateCgroup(id uint64, cgroupPath string) error {
	if !c.checkMatch(cgroupPath) {
		return nil
	}
	value := uint64(1)
	var err error
	switch c.bpfMapType {
	case config.CgroupIDMapHashType:
		err = c.bpfMap.Update(unsafe.Pointer(&id), unsafe.Pointer(&value))
	case config.CgroupIDMapCgrpStorageType:
		var cgroupFile *os.File
		// https://docs.kernel.org/bpf/map_cgrp_storage.html
		// we need an open cgroup fd to update cgroup map
		cgroupFile, err = os.Open(cgroupPath)
		if err != nil {
			log.Printf("Error opening cgroup path %s: %v", cgroupPath, err)
		} else {
			fd := cgroupFile.Fd()
			err = c.bpfMap.Update(unsafe.Pointer(&fd), unsafe.Pointer(&value))
			cgroupFile.Close()
		}
	}

	return err
}

func (c *CgroupIDMap) checkMatch(path string) bool {
	for _, compiled := range c.cache {
		if compiled.MatchString(path) {
			return true
		}
	}
	return false
}
