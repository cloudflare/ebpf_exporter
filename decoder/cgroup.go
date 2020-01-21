 package decoder

import (
  "os"
  "fmt"
  "log"
  "strconv"
  "path/filepath"

  "golang.org/x/sys/unix"
	"github.com/cloudflare/ebpf_exporter/config"
  "github.com/iovisor/gobpf/bcc"
)

// CGroup is a decoder that transforms cgroup id to path in cgroupfs
type CGroup struct {
	cache map[uint64][]byte
}

// Decode transforms cgroup id to path in cgroupfs
func (c *CGroup) Decode(in []byte, conf config.Decoder) ([]byte, error) {
  if c.cache == nil {
    c.cache = map[uint64][]byte{}
  }

  cgroupID, err := strconv.Atoi(string(in))
  if err != nil {
    return nil, err
  }

  if path, ok := c.cache[uint64(cgroupID)]; ok {
    return path, nil
  }

  if err = c.refreshCache(); err != nil {
    log.Printf("Error refreshing cgroup id to path map: %s", err)
  }

  if path, ok := c.cache[uint64(cgroupID)]; ok {
    return path, nil
  }

  return []byte(fmt.Sprintf("unknown_cgroup_id:%d", cgroupID)), nil
}

func (c *CGroup) refreshCache() error {
  byteOrder := bcc.GetHostByteOrder()

  cgroupPath := "/sys/fs/cgroup/unified"
  if _, err := os.Stat(cgroupPath); os.IsNotExist(err) {
    cgroupPath = "/sys/fs/cgroup"
  }

  return filepath.Walk(cgroupPath, func(path string, info os.FileInfo, err error) error {
    if err != nil {
      return err
    }

    if !info.IsDir() {
      return nil
    }

    handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
    if err != nil {
      log.Printf("Error resolving handle of %s: %s", path, err)
    }

    c.cache[byteOrder.Uint64(handle.Bytes())] = []byte(path)

    return nil
  })
}
