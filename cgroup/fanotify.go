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
	"strings"
	"syscall"

	"github.com/cloudflare/ebpf_exporter/v2/util"
	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// mountEntry holds an open fd for a cgroup mount, keyed by device id for event handling.
type mountEntry struct {
	path string
	file *os.File
	dev  uint64
}

type fanotifyMonitor struct {
	path      string
	fanotify  io.Reader
	mounts    []mountEntry
	observer  *observer
	byteOrder binary.ByteOrder
}

func collectCgroupMountsByPrefix(prefix string) ([]string, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseMountinfoForPrefix(f, prefix)
}

// parseMountinfoForPrefix reads a mountinfo-formatted stream and returns mount points
// that equal prefix or are under prefix (prefix/...).
func parseMountinfoForPrefix(r io.Reader, prefix string) ([]string, error) {
	var out []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		i := strings.Index(line, " - ")
		if i < 0 {
			continue
		}
		fields := strings.Fields(line[:i])
		if len(fields) < 5 {
			continue
		}
		mountPoint := fields[4]
		if mountPoint == prefix || strings.HasPrefix(mountPoint, prefix+"/") {
			out = append(out, mountPoint)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func newFanotifyMonitor(path string) (*fanotifyMonitor, error) {
	dacAllowed, err := cap.GetProc().GetFlag(cap.Effective, cap.DAC_READ_SEARCH)
	if err != nil {
		return nil, err
	}
	if !dacAllowed {
		return nil, errors.New("missing CAP_DAC_READ_SEARCH needed for open_by_handle_at in fanotify monitor")
	}

	mountPaths, err := collectCgroupMountsByPrefix(path)
	if err != nil {
		return nil, fmt.Errorf("discovering cgroup mounts under %q: %w", path, err)
	}
	if len(mountPaths) == 0 {
		mountPaths = []string{path}
	}

	fanotify, mounts, err := attachFanotifyMultiple(mountPaths)
	if err != nil {
		return nil, err
	}

	initial, err := walk(path)
	if err != nil {
		for _, e := range mounts {
			_ = e.file.Close()
		}
		return nil, err
	}

	observer := newObserver(initial)

	m := &fanotifyMonitor{
		path:      path,
		fanotify:  fanotify,
		mounts:    mounts,
		observer:  observer,
		byteOrder: util.GetHostByteOrder(),
	}

	go func() {
		err := m.readFanotifyLoop()
		log.Fatalf("Fanotify loop terminated with err:%v", err)
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
		_ = unix.Close(int(metadata.Fd))
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

	var st unix.Stat_t
	if err := unix.Fstat(int(metadata.Fd), &st); err != nil {
		return fmt.Errorf("error fstat on event fd: %w", err)
	}
	dev := uint64(st.Dev)
	var mountFd int
	for i := range m.mounts {
		if m.mounts[i].dev == dev {
			mountFd = int(m.mounts[i].file.Fd())
			break
		}
	}
	if mountFd == 0 {
		return fmt.Errorf("no mount found for event device %d", dev)
	}

	fd, err := unix.OpenByHandleAt(mountFd, handle, 0)
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

func (m *fanotifyMonitor) SubscribeCgroupChange(ch chan<- ChangeNotification) error {
	return m.observer.subscribeCgroupChange(ch)
}

// The following kernel patch is required to take advantage of this (included in v6.6-rc1):
// * https://git.kernel.org/torvalds/c/0ce7c12e88cf ("kernfs: attach uuid for every kernfs and report it in fsid")
func attachFanotifyMultiple(paths []string) (io.Reader, []mountEntry, error) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_REPORT_DFID_NAME, uint(0))
	if err != nil {
		return nil, nil, fmt.Errorf("error calling fanotify_init: %w", err)
	}

	var mounts []mountEntry
	cleanup := func() {
		for _, e := range mounts {
			_ = e.file.Close()
		}
		unix.Close(fd)
	}

	for _, p := range paths {
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_ONLYDIR|unix.FAN_MARK_FILESYSTEM, unix.FAN_CREATE|unix.FAN_DELETE|unix.FAN_ONDIR, unix.AT_FDCWD, p); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("error calling fanotify_mark for %q: %w", p, err)
		}
		file, err := os.OpenFile(p, syscall.O_DIRECTORY, 0)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("error opening mount %q: %w", p, err)
		}
		var st unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &st); err != nil {
			file.Close()
			cleanup()
			return nil, nil, fmt.Errorf("error fstat on %q: %w", p, err)
		}
		mounts = append(mounts, mountEntry{path: p, file: file, dev: uint64(st.Dev)})
	}

	return bufio.NewReader(os.NewFile(uintptr(fd), "")), mounts, nil
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
