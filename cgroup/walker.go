package cgroup

import (
	"io/fs"
	"log"
	"path/filepath"
)

type walkerMonitor struct {
	path    string
	mapping map[int]string
}

func newWalkerMonitor(path string) (*walkerMonitor, error) {
	mapping, err := walk(path)
	if err != nil {
		return nil, err
	}

	return &walkerMonitor{path: path, mapping: mapping}, nil
}

func (m *walkerMonitor) Resolve(id int) string {
	// Try to resolve in cache first
	if existing, ok := m.mapping[id]; ok {
		return existing
	}

	// Refresh mapping to see if we a new cgroup appeared since last time
	if mapping, err := walk(m.path); err != nil {
		log.Printf("Error refreshing mapping: %v", err)
	} else {
		for id, name := range mapping {
			m.mapping[id] = name
		}
	}

	// If no new cgroup appeared, cache negative resolution to prevent constant refreshes
	if _, ok := m.mapping[id]; !ok {
		m.mapping[id] = ""
	}

	// Return whatever we have now (either newly resolved or cached negative value)
	return m.mapping[id]
}

func walk(dir string) (map[int]string, error) {
	mapping := map[int]string{}

	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !entry.IsDir() {
			return nil
		}

		inode, err := inode(path)
		if err != nil {
			log.Printf("Error resolving inode for %q: %v", path, err)
			return nil
		}

		mapping[inode] = path

		return nil
	})

	return mapping, err
}
