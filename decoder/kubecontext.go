package decoder

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/iovisor/gobpf/bcc"

	"github.com/cloudflare/ebpf_exporter/config"
	"github.com/docker/docker/client"
)

const (
	// when fail get kubernetes labe fail use DefaultKubeContextValue  as default
	DefaultKubeContextValue = "unknown"
)

// KubeInfo kubernetes context info
type KubeInfo struct {
	kubePodNamespace  string
	kubePodName       string
	kubeContainerName string
}

// KubeContext kubernetes context info cache
type KubeContext struct {
	kubeContext map[string]KubeInfo
}

// KubePodNamespace is a decoder that transforms pid representation into kubernetes pod namespace
type KubePodNamespace struct {
	ctx KubeContext
}

// KubePodName is a decoder that transforms pid representation into kubernetes pod name
type KubePodName struct {
	ctx KubeContext
}

// KubeContainerName is a decoder that transforms pid representation into kubernetes pod container name
type KubeContainerName struct {
	ctx KubeContext
}

// KubeContainerNameOrPid is a decoder that transforms pid representation into kubernetes pod container name or pid
type KubeContainerNameOrPid struct {
	ctx KubeContext
}

// Decode transforms pid representation into a kubernetes namespace and pod as string
func (k *KubePodNamespace) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	byteOrder := bcc.GetHostByteOrder()
	info := k.ctx.getKubeInfo(byteOrder.Uint32(in))
	b := []byte(info.kubePodNamespace)
	return b, nil
}

// Decode transforms pid representation into a kubernetes pod name as string
func (k *KubePodName) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	byteOrder := bcc.GetHostByteOrder()
	info := k.ctx.getKubeInfo(byteOrder.Uint32(in))
	b := []byte(info.kubePodName)
	return b, nil
}

// Decode transforms pid representation into a kubernetes container name as string
func (k *KubeContainerName) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	byteOrder := bcc.GetHostByteOrder()
	info := k.ctx.getKubeInfo(byteOrder.Uint32(in))
	b := []byte(info.kubeContainerName)
	return b, nil
}

// Decode transforms pid representation into a kubernetes container name, if no foud return pid instead
func (k *KubeContainerNameOrPid) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	byteOrder := bcc.GetHostByteOrder()
	info := k.ctx.getKubeInfo(byteOrder.Uint32(in))
	if info.kubeContainerName == DefaultKubeContextValue {
		info.kubeContainerName = fmt.Sprintf("pid-%d", byteOrder.Uint32(in))
	}
	b := []byte(info.kubeContainerName)
	return b, nil
}

// getKubeInfo implement main logic convert container id to kubernetes context
func (k *KubeContext) getKubeInfo(pid uint32) (info KubeInfo) {
	info.kubePodNamespace = DefaultKubeContextValue
	info.kubePodName = DefaultKubeContextValue
	info.kubeContainerName = DefaultKubeContextValue
	path := fmt.Sprintf("/proc/%d/cgroup", pid)

	r, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() {
		if rerr := r.Close(); rerr != nil {
			err = rerr
		}
	}()

	s := bufio.NewScanner(r)

	for s.Scan() {
		text := s.Text()
		//hierarchy-ID:subsystem-list:cgroup-path
		parts := strings.SplitN(text, ":", 3)
		if len(parts) < 3 {
			continue
		}
		cgroup := strings.Split(parts[2], "/")
		containerID := cgroup[len(cgroup)-1]
		if len(containerID) == 64 {
			info = k.inspectKubeInfo(containerID)
			return
		}
	}
	return
}

// inspectKubeInfo use docker client library to get kubernetes labels value
func (k *KubeContext) inspectKubeInfo(containerID string) (info KubeInfo) {
	/// store more than 1000 container, need clean it for reduce memory use
	if k.kubeContext == nil || len(k.kubeContext) > 1000 {
		k.kubeContext = make(map[string]KubeInfo)
	}
	var ok bool
	info, ok = k.kubeContext[containerID]
	if ok {
		return
	}
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return
	}
	defer func() {
		if cerr := cli.Close(); cerr != nil {
			err = cerr
		}
	}()
	filters := filters.NewArgs()
	if len(k.kubeContext) > 0 {
		filters.Add("id", containerID)
	}
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{
		Filters: filters,
	})
	if err != nil {
		return
	}

	for _, container := range containers {
		if container.Labels != nil {
			var tmp KubeInfo
			tmp.kubePodNamespace, _ = container.Labels["io.kubernetes.pod.namespace"]
			if tmp.kubePodNamespace == "" {
				tmp.kubePodNamespace = DefaultKubeContextValue
			}
			tmp.kubePodName = container.Labels["io.kubernetes.pod.name"]
			if tmp.kubePodName == "" {
				tmp.kubePodName = DefaultKubeContextValue
			}
			tmp.kubeContainerName = container.Labels["io.kubernetes.container.name"]
			if tmp.kubeContainerName == "" {
				tmp.kubeContainerName = DefaultKubeContextValue
			}
			k.kubeContext[container.ID] = tmp
		}
	}
	info, _ = k.kubeContext[containerID]
	return
}
