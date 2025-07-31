package cgroup

import (
	"errors"
	"log"
)

// ErrCgroupIDMapUnsupported is returned when cgroup id map is not available
var ErrCgroupIDMapUnsupported = errors.New("cgroup change subscription failed (fanotify not available)")

// ChangeNotification is the notification returned by cgroup monitor when a subscribed
// cgroup has been added or removed
type ChangeNotification struct {
	ID     int
	Path   string
	Remove bool
}

type monitor interface {
	Resolve(id int) string
	SubscribeCgroupChange(ch chan<- ChangeNotification) error
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

// SubscribeCgroupChange receives cgroup change notifications. This requires
// kernel with fanotify support for cgroup
func (m *Monitor) SubscribeCgroupChange(ch chan<- ChangeNotification) error {
	return m.inner.SubscribeCgroupChange(ch)
}
