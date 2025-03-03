package cgroup

import (
	"errors"
	"log"
)

var ErrCgroupIdMapUnsupported = errors.New("cgroup change subscription failed (fanotify not available)")

type CgroupChange struct {
	Id     int
	Path   string
	Remove bool
}

type monitor interface {
	Resolve(id int) string
	SubscribeCgroupChange(chan<- CgroupChange) error
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

func (m *Monitor) SubscribeCgroupChange(ch chan<- CgroupChange) error {
	return m.inner.SubscribeCgroupChange(ch)
}
