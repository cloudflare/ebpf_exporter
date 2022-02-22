
package exporter

import (
	"fmt"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/util"
)

// mergeTags runs attacher and merges produced tags
func mergedTags(dst map[string]string, src map[string]string) error {
	for name, tag := range src {
		dst[name] = tag
	}
	return nil
}

// attach attaches functions to tracing points in provided module
func attach(module *bpf.Module, kprobes, kretprobes, tracepoints, rawTracepoints map[string]string) (map[string]string, error) {
	tags := map[string]string{}

	probes, err := attachSomething(module, kprobes, "kprobe")
	if err != nil {
		return nil, fmt.Errorf("failed to attach kprobes: %s", err)
	}
	mergedTags(tags, probes)

	probes, err = attachSomething(module, kretprobes, "kretprobe")
	if err != nil {
		return nil, fmt.Errorf("failed to attach kretprobes: %s", err)
	}
	mergedTags(tags, probes)

	probes, err = attachSomething(module, tracepoints, "tracepoint")
	if err != nil {
		return nil, fmt.Errorf("failed to attach tracepoints: %s", err)
	}
	mergedTags(tags, probes)

	probes, err = attachSomething(module, rawTracepoints, "rawtracepoint")
	if err != nil {
		return nil, fmt.Errorf("failed to attach raw tracepoints: %s", err)
	}
	mergedTags(tags, probes)

	return tags, nil
}
// attachSomething attaches some kind of probes and returns program tags
func attachSomething(module *bpf.Module, probes map[string]string, key string) (map[string]string, error) {
	tags := map[string]string{}

	for probe, targetName := range probes {
		prog, err := module.GetProgram(targetName)
		if err != nil {
			return nil, fmt.Errorf("Can't get  program:%v err:%v", targetName, err)
		}
		fd := prog.GetFd()
		var tag string
		err = util.ScanFdInfo(fd,  map[string]interface{}{
			"prog_tag":  &tag,
		})
        if err != nil {
			return nil, fmt.Errorf("Can't get tag of program:%v err:%v", targetName, err)
		}
		tags[targetName] = tag
		switch key {
		case "kprobe":
			_, err = prog.AttachKprobe(probe)
		case "kretprobe":
			_, err = prog.AttachKretprobe(probe)
		case "tracepoint":
			_, err = prog.AttachTracepoint(probe)
		case "rawtracepoint":
			_, err = prog.AttachRawTracepoint(probe)
		}
		if err != nil {
			return nil, fmt.Errorf("Can't attach probe:%v err:%v", probe, err)
		}
	}
	return tags, nil
}
