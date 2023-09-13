package cgroup

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"syscall"

	"github.com/cloudflare/ebpf_exporter/v2/util"
	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

type fanotifyMonitor struct {
	path      string
	fanotify  io.Reader
	mount     *os.File
	mapping   map[int]string
	lock      sync.RWMutex
	byteOrder binary.ByteOrder
}

func newFanotifyMonitor(path string) (*fanotifyMonitor, error) {
	fanotify, err := attachFanotify(path)
	if err != nil {
		return nil, err
	}

	mount, err := os.OpenFile(path, syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("error opening %q: %v", path, err)
	}

	dacAllowed, err := cap.GetProc().GetFlag(cap.Effective, cap.DAC_READ_SEARCH)
	if err != nil {
		return nil, err
	}

	if !dacAllowed {
		return nil, fmt.Errorf("missing CAP_DAC_READ_SEARCH needed for open_by_handle_at in fanotify monitor")
	}

	mapping, err := walk(path)
	if err != nil {
		return nil, err
	}

	byteOrder := util.GetHostByteOrder()

	m := &fanotifyMonitor{
		path:      path,
		fanotify:  fanotify,
		mount:     mount,
		mapping:   mapping,
		lock:      sync.RWMutex{},
		byteOrder: byteOrder,
	}

	go func() {
		if err := m.readFanotifyLoop(); err != nil {
			log.Fatalf("Error running fanotify loop: %v", err)
		}
	}()

	return m, nil
}

func (m *fanotifyMonitor) readFanotifyLoop() error {
	metadata := unix.FanotifyEventMetadata{}

	// This needs to fit filename (up to 255 chars) and some small-ish headers
	buf := make([]byte, 512)

	for {
		if err := binary.Read(m.fanotify, m.byteOrder, &metadata); err != nil {
			return fmt.Errorf("error reading fanotify event: %v", err)
		}

		if metadata.Vers != unix.FANOTIFY_METADATA_VERSION {
			return fmt.Errorf("wrong fanotify event version: %#v", metadata)
		}

		if metadata.Mask&unix.FAN_CREATE == 0 {
			return fmt.Errorf("fanotify event for non-create event")
		}

		if metadata.Mask&unix.FAN_ONDIR == 0 {
			return fmt.Errorf("fanotify event for non-directory")
		}

		size := int(metadata.Event_len) - int(metadata.Metadata_len)
		if size > 0 {
			if _, err := m.fanotify.Read(buf[:size]); err != nil {
				return fmt.Errorf("error reading extra stuff: %v", err)
			}
		}

		if err := m.handleFanotify(&metadata, buf[:size]); err != nil {
			return fmt.Errorf("error handling fanotify event: %v", err)
		}
	}
}

func (m *fanotifyMonitor) handleFanotify(_ *unix.FanotifyEventMetadata, buf []byte) error {
	reader := bufio.NewReader(bytes.NewReader(buf))

	header := fanotifyEventInfoFid{}
	if err := binary.Read(reader, m.byteOrder, &header); err != nil {
		return fmt.Errorf("error reading fanotify header: %v", err)
	}

	if header.Header.Type != unix.FAN_EVENT_INFO_TYPE_DFID_NAME {
		return fmt.Errorf("unexpected fanotify header type 0x%x (expected 0x%x / FAN_EVENT_INFO_TYPE_DFID_NAME)", header.Header.Type, unix.FAN_EVENT_INFO_TYPE_DFID_NAME)
	}

	handle, err := m.readFanotifyFileHandle(reader)
	if err != nil {
		return fmt.Errorf("error reading file_handle: %v", err)
	}

	fd, err := unix.OpenByHandleAt(int(m.mount.Fd()), handle, 0)
	if err != nil {
		return fmt.Errorf("error opening event fd: %v", err)
	}

	defer syscall.Close(fd)

	name, err := reader.ReadString('\x00')
	if err != nil {
		return fmt.Errorf("error reading name: %v", err)
	}

	// Truncate \x00 at the end
	name = name[:len(name)-1]

	stat := unix.Stat_t{}
	err = unix.Fstatat(fd, name, &stat, 0)
	if err != nil {
		// Sometimes we can't get the inode in type and it shouldn't be a fatal error
		log.Printf("Error calling fstatat for %q: %v", name, err)
		return nil
	}

	dir, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return fmt.Errorf("error resolving event fd symlink: %v", err)
	}

	path := fmt.Sprintf("%s/%s", dir, name)

	m.lock.Lock()
	m.mapping[int(stat.Ino)] = path
	m.lock.Unlock()

	return nil
}

// Reading struct file_handle piece by piece:
// https://elixir.bootlin.com/linux/v6.5-rc1/source/include/linux/fs.h#L1002
func (m *fanotifyMonitor) readFanotifyFileHandle(reader io.Reader) (unix.FileHandle, error) {
	handleBytes := uint32(0)
	if err := binary.Read(reader, binary.LittleEndian, &handleBytes); err != nil {
		return unix.FileHandle{}, fmt.Errorf("error reading file_handle->handle_bytes: %v", err)
	}

	handleType := int32(0)
	if err := binary.Read(reader, binary.LittleEndian, &handleType); err != nil {
		return unix.FileHandle{}, fmt.Errorf("error reading file_handle->handle_type: %v", err)
	}

	handle := make([]byte, handleBytes)
	if _, err := reader.Read(handle); err != nil {
		return unix.FileHandle{}, fmt.Errorf("error reading file_handle->handle (%d bytes): %v", handleBytes, err)
	}

	return unix.NewFileHandle(handleType, handle), nil
}

func (m *fanotifyMonitor) Resolve(id int) string {
	m.lock.RLock()
	defer m.lock.RUnlock()
	return m.mapping[id]
}

// The following kernel patch is required to take advantage of this (included in v6.6-rc1):
// * https://github.com/torvalds/linux/commit/0ce7c12e88cf
func attachFanotify(path string) (io.Reader, error) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_REPORT_DFID_NAME, uint(0))
	if err != nil {
		return nil, fmt.Errorf("error calling fanotify_init: %v", err)
	}

	err = unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_ONLYDIR|unix.FAN_MARK_FILESYSTEM, unix.FAN_CREATE|unix.FAN_ONDIR, unix.AT_FDCWD, path)
	if err != nil {
		return nil, fmt.Errorf("error calling fanotify_mark for %q: %v", path, err)
	}

	return bufio.NewReader(os.NewFile(uintptr(fd), "")), nil
}

type fanotifyEventInfoFid struct {
	Header fanotifyEventInfoHeader
	Fsid   unix.Fsid
}

type fanotifyEventInfoHeader struct {
	Type uint8
	Pad  uint8
	Len  uint16
}
