package cgroup

import (
	"fmt"
	"os"
	"testing"
	"time"
)

const preExistingFile = "i-was-here"
const sleepDuration = time.Millisecond * 5

func TestMonitor(t *testing.T) {
	cases := []struct {
		kind    string
		check   func() bool
		factory func(path string) (monitor, error)
	}{
		{
			kind: "Monitor",
			factory: func(path string) (monitor, error) {
				return NewMonitor(path)
			},
		},
		{
			kind: "walkerMonitor",
			factory: func(path string) (monitor, error) {
				return newWalkerMonitor(path)
			},
		},
		{
			kind: "fanotifyMonitor",
			check: func() bool {
				// Only test fanotify under root
				return os.Geteuid() == 0
			},
			factory: func(path string) (monitor, error) {
				return newFanotifyMonitor(path)
			},
		},
	}

	for _, c := range cases {
		t.Run(c.kind, func(t *testing.T) {
			path := t.TempDir()

			preExistingPath := fmt.Sprintf("%s/%s", path, preExistingFile)
			if err := os.Mkdir(preExistingPath, 0755); err != nil {
				t.Fatalf("Error creating %q: %v", preExistingPath, err)
			}

			if c.check != nil && !c.check() {
				t.Skip()
			}

			m, err := c.factory(path)
			if err != nil {
				t.Fatal(err)
			}

			if m == nil {
				t.Skip()
			}

			testMonitor(t, m, path, preExistingPath)
		})
	}
}

func testMonitor(t *testing.T, m monitor, path, preExistingPath string) {
	preExistingID, err := inode(preExistingPath)
	if err != nil {
		t.Fatalf("Error resolving %q: %v", preExistingPath, err)
	}

	preExistingResolved := m.Resolve(preExistingID)
	if preExistingResolved != preExistingPath {
		t.Errorf("Expected %d to resolve into pre-existing %q, got %q", preExistingID, preExistingPath, preExistingResolved)
	}

	// What are the chances?
	missingName := m.Resolve(88888888888)

	if missingName != "" {
		t.Errorf("Expected empty string for a missing inode, got %q", missingName)
	}

	// Check addition one by one
	for i := 0; i < 20; i++ {
		dir := fmt.Sprintf("%s/lol-%d", path, i)

		err = os.Mkdir(dir, 0755)
		if err != nil {
			t.Fatalf("Error creating %q: %v", dir, err)
		}

		// Sleep for a short time to let fanotify to process
		time.Sleep(sleepDuration)

		id, err := inode(dir)
		if err != nil {
			t.Fatalf("Error resolving %q: %v", dir, err)
		}

		resolved := m.Resolve(id)
		if resolved != dir {
			t.Errorf("Expected %q, got %q", dir, resolved)
		}
	}

	// Check burst addition
	for i := 20; i < 40; i++ {
		dir := fmt.Sprintf("%s/lol-%d", path, i)

		err = os.Mkdir(dir, 0755)
		if err != nil {
			t.Fatalf("Error creating %q: %v", dir, err)
		}
	}

	// Sleep for a short time to let fanotify to process
	time.Sleep(sleepDuration)

	// Continue checking burst addition
	for i := 20; i < 40; i++ {
		dir := fmt.Sprintf("%s/lol-%d", path, i)

		id, err := inode(dir)
		if err != nil {
			t.Fatalf("Error resolving %q: %v", dir, err)
		}

		resolved := m.Resolve(id)
		if resolved != dir {
			t.Errorf("Expected %q, got %q", dir, resolved)
		}
	}

	// Check if overwrites are picked up
	overwritePath := fmt.Sprintf("%s/%s", path, "lol-22")

	idBefore, err := inode(overwritePath)
	if err != nil {
		t.Fatalf("Error resolving %q (before): %v", overwritePath, err)
	}

	resolvedBefore := m.Resolve(idBefore)
	if resolvedBefore != overwritePath {
		t.Errorf("Expected %d to resolve into %q, got %q (before)", idBefore, overwritePath, resolvedBefore)
	}

	err = os.Remove(overwritePath)
	if err != nil {
		t.Fatalf("Error removing %q: %v", overwritePath, err)
	}

	err = os.Mkdir(overwritePath, 0755)
	if err != nil {
		t.Fatalf("Error re-creating %q: %v", overwritePath, err)
	}

	idAfter, err := inode(overwritePath)
	if err != nil {
		t.Fatalf("Error resolving %q (after): %v", overwritePath, err)
	}

	// Sleep for a short time to let fanotify to process
	time.Sleep(sleepDuration)

	resolvedAfter := m.Resolve(idAfter)
	if resolvedAfter != overwritePath {
		t.Errorf("Expected %d to resolve into %q, got %q (after)", idAfter, overwritePath, resolvedAfter)
	}
}
