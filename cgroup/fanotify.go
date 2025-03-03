package cgroup

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"syscall"

	"github.com/cloudflare/ebpf_exporter/v2/util"
	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

type fanotifyMonitor struct {
	path      string
	fanotify  io.Reader
	mount     *os.File
	observer  *observer
	byteOrder binary.ByteOrder
}

func newFanotifyMonitor(path string) (*fanotifyMonitor, error) {
	fanotify, err := attachFanotify(path)
	if err != nil {
		return nil, err
	}

	mount, err := os.OpenFile(path, syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("error opening %q: %w", path, err)
	}

	dacAllowed, err := cap.GetProc().GetFlag(cap.Effective, cap.DAC_READ_SEARCH)
	if err != nil {
		return nil, err
	}

	if !dacAllowed {
		return nil, errors.New("missing CAP_DAC_READ_SEARCH needed for open_by_handle_at in fanotify monitor")
	}

	initial, err := walk(path)
	if err != nil {
		return nil, err
	}

	observer := newObserver(initial)

	byteOrder := util.GetHostByteOrder()

	m := &fanotifyMonitor{
		path:      path,
		fanotify:  fanotify,
		mount:     mount,
		observer:  observer,
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
			return fmt.Errorf("error reading fanotify event: %w", err)
		}

		if metadata.Vers != unix.FANOTIFY_METADATA_VERSION {
			return fmt.Errorf("wrong fanotify event version: %#v", metadata)
		}

		if metadata.Mask&unix.FAN_CREATE == 0 && metadata.Mask&unix.FAN_DELETE == 0 {
			return errors.New("fanotify event for non-create and non-delete event")
		}

		if metadata.Mask&unix.FAN_ONDIR == 0 {
			return errors.New("fanotify event for non-directory")
		}

		size := int(metadata.Event_len) - int(metadata.Metadata_len)
		if size > 0 {
			if _, err := m.fanotify.Read(buf[:size]); err != nil {
				return fmt.Errorf("error reading extra stuff: %w", err)
			}
		}

		if err := m.handleFanotify(&metadata, buf[:size]); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("error handling fanotify event: %w", err)
			}
		}
	}
}

func (m *fanotifyMonitor) handleFanotify(metadata *unix.FanotifyEventMetadata, buf []byte) error {
	reader := bufio.NewReader(bytes.NewReader(buf))

	header := fanotifyEventInfoFid{}
	if err := binary.Read(reader, m.byteOrder, &header); err != nil {
		return fmt.Errorf("error reading fanotify header: %w", err)
	}

	if header.Header.Type != unix.FAN_EVENT_INFO_TYPE_DFID_NAME {
		return fmt.Errorf("unexpected fanotify header type 0x%x (expected 0x%x / FAN_EVENT_INFO_TYPE_DFID_NAME)", header.Header.Type, unix.FAN_EVENT_INFO_TYPE_DFID_NAME)
	}

	handle, err := m.readFanotifyFileHandle(reader)
	if err != nil {
		return fmt.Errorf("error reading file_handle: %w", err)
	}

	fd, err := unix.OpenByHandleAt(int(m.mount.Fd()), handle, 0)
	if err != nil {
		// This happens in tests when walkerMonitor runs after fanotify.
		// No idea why it happens, so let's just ignore it for now.
		if errors.Is(err, unix.ESTALE) && metadata.Mask&unix.FAN_DELETE != 0 {
			return nil
		}

		return fmt.Errorf("error opening event fd: %w", err)
	}

	defer syscall.Close(fd)

	name, err := reader.ReadString('\x00')
	if err != nil {
		return fmt.Errorf("error reading name: %w", err)
	}

	// Truncate \x00 at the end
	name = name[:len(name)-1]

	stat := unix.Stat_t{}

	if metadata.Mask&unix.FAN_CREATE != 0 {
		err = unix.Fstatat(fd, name, &stat, 0)
		if err != nil {
			return fmt.Errorf("error calling fstatat for %q: %w", name, err)
		}
	}

	// Path needs to be resolved after fstatat() for FAN_CREATE,
	// otherwise the directory can be missed if it is short lived.
	dir, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return fmt.Errorf("error resolving event fd symlink: %w", err)
	}

	path := fmt.Sprintf("%s/%s", dir, name)

	if metadata.Mask&unix.FAN_CREATE != 0 {
		m.observer.add(int(stat.Ino), path)
	} else {
		m.observer.remove(path)
	}

	return nil
}

// Reading struct file_handle piece by piece:
// https://elixir.bootlin.com/linux/v6.5-rc1/source/include/linux/fs.h#L1002
func (m *fanotifyMonitor) readFanotifyFileHandle(reader io.Reader) (unix.FileHandle, error) {
	handleBytes := uint32(0)
	if err := binary.Read(reader, binary.LittleEndian, &handleBytes); err != nil {
		return unix.FileHandle{}, fmt.Errorf("error reading file_handle->handle_bytes: %w", err)
	}

	handleType := int32(0)
	if err := binary.Read(reader, binary.LittleEndian, &handleType); err != nil {
		return unix.FileHandle{}, fmt.Errorf("error reading file_handle->handle_type: %w", err)
	}

	handle := make([]byte, handleBytes)
	if _, err := reader.Read(handle); err != nil {
		return unix.FileHandle{}, fmt.Errorf("error reading file_handle->handle (%d bytes): %w", handleBytes, err)
	}

	return unix.NewFileHandle(handleType, handle), nil
}

func (m *fanotifyMonitor) Resolve(id int) string {
	return m.observer.lookup(id)
}

func (m *fanotifyMonitor) SubscribeCgroupChange(ch chan<- CgroupChange) error {
	return m.observer.subscribeCgroupChange(ch)
}

// The following kernel patch is required to take advantage of this (included in v6.6-rc1):
// * https://git.kernel.org/torvalds/c/0ce7c12e88cf ("kernfs: attach uuid for every kernfs and report it in fsid")
func attachFanotify(path string) (io.Reader, error) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_REPORT_DFID_NAME, uint(0))
	if err != nil {
		return nil, fmt.Errorf("error calling fanotify_init: %w", err)
	}

	err = unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_ONLYDIR|unix.FAN_MARK_FILESYSTEM, unix.FAN_CREATE|unix.FAN_DELETE|unix.FAN_ONDIR, unix.AT_FDCWD, path)
	if err != nil {
		return nil, fmt.Errorf("error calling fanotify_mark for %q: %w", path, err)
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
