package cgroup

import (
	"log"
)

type monitor interface {
	Resolve(int) string
}

// Monitor resolves cgroup ids into their respective paths
type Monitor struct {
	inner monitor
}

// NewMonitor returns a new cgroup monitor for a given path
func NewMonitor(path string) (*Monitor, error) {
	fm, err := newFanotifyMonitor(path)
	if err != nil {
		log.Printf("Using on-demand resolution for cgroups (fanotify not available)")

		wm, err := newWalkerMonitor(path)
		if err != nil {
			return nil, err
		}

		return &Monitor{inner: wm}, nil
	}

	return &Monitor{inner: fm}, nil
}

// Resolve resolves an id to a path for a cgroup
func (m *Monitor) Resolve(id int) string {
	return m.inner.Resolve(id)
}
