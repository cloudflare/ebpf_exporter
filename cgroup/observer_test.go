package cgroup

import "testing"

func TestObserverGC(t *testing.T) {
	observer := newObserver(map[int]string{})

	observer.add(1, "potato")

	value := observer.lookup(1)
	if value != "potato" {
		t.Fatalf("expected potato, got %q", value)
	}

	observer.remove("potato")

	observer.gc(true)

	value = observer.lookup(1)
	if value != "" {
		t.Fatalf("expected nothing, got %q", value)
	}

	if len(observer.inodeToPath) != len(observer.pathToInode) {
		t.Fatalf("expected len(inodeToPath) [%d] to be equal len(pathToInode) [%d]", len(observer.inodeToPath), len(observer.pathToInode))
	}
}

func TestObserverLiveness(t *testing.T) {
	observer := newObserver(map[int]string{})

	observer.add(1, "potato")

	value := observer.lookup(1)
	if value != "potato" {
		t.Fatalf("expected potato, got %q", value)
	}

	observer.remove("potato")

	observer.add(1, "tomato")

	observer.gc(true)

	value = observer.lookup(1)
	if value != "tomato" {
		t.Fatalf("expected tomato, got %q", value)
	}

	if len(observer.inodeToPath) != len(observer.pathToInode) {
		t.Fatalf("expected len(inodeToPath) [%d] to be equal len(pathToInode) [%d]", len(observer.inodeToPath), len(observer.pathToInode))
	}
}
