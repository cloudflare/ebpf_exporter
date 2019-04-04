package exporter

import (
	"fmt"

	"github.com/iovisor/gobpf/bcc"
)

// attacher attaches some sort of tracepoints or probes
type attacher func(*bcc.Module, map[string]string) (map[string]uint64, error)

// mergeTags runs attacher and merges produced tags
func mergedTags(dst map[string]uint64, attach attacher, module *bcc.Module, attachments map[string]string) error {
	src, err := attach(module, attachments)

	if err != nil {
		return err
	}

	for name, tag := range src {
		dst[name] = tag
	}

	return nil
}

// attach attaches functions to tracing points in provided module
func attach(module *bcc.Module, kprobes, kretprobes, tracepoints, rawTracepoints map[string]string) (map[string]uint64, error) {
	tags := map[string]uint64{}

	if err := mergedTags(tags, attachKprobes, module, kprobes); err != nil {
		return nil, fmt.Errorf("failed to attach kprobes: %s", err)
	}

	if err := mergedTags(tags, attachKretprobes, module, kretprobes); err != nil {
		return nil, fmt.Errorf("failed to attach kretprobes: %s", err)
	}

	if err := mergedTags(tags, attachTracepoints, module, tracepoints); err != nil {
		return nil, fmt.Errorf("failed to attach tracepoints: %s", err)
	}

	if err := mergedTags(tags, attachRawTracepoints, module, rawTracepoints); err != nil {
		return nil, fmt.Errorf("failed to attach raw tracepoints: %s", err)
	}

	return tags, nil
}

// probeLoader attaches some sort of probe
type probeLoader func(string) (int, error)

// probeAttacher attaches loaded some sort of probe to some sort of tracepoint
type probeAttacher func(string, int) error
type probeAttacherWithMaxActive func(string, int, int) error

// attachSomething attaches some kind of probes and returns program tags
func attachSomething(module *bcc.Module, loader probeLoader, attacher probeAttacher, probes map[string]string) (map[string]uint64, error) {
	tags := map[string]uint64{}

	for probe, targetName := range probes {
		target, err := loader(targetName)
		if err != nil {
			return nil, fmt.Errorf("failed to load probe %q: %s", targetName, err)
		}

		tag, err := module.GetProgramTag(target)
		if err != nil {
			return nil, fmt.Errorf("failed to get program tag for %q (fd=%d): %s", targetName, target, err)
		}

		tags[targetName] = tag

		err = attacher(probe, target)
		if err != nil {
			return nil, fmt.Errorf("failed to attach probe %q to %q: %s", probe, targetName, err)
		}
	}

	return tags, nil
}

// withMaxActive partially applies the maxactive value as needed by AttackK*probe
func withMaxActive(attacherWithMaxActive probeAttacherWithMaxActive, maxActive int) probeAttacher {
	return func(probe string, target int) error {
		return attacherWithMaxActive(probe, target, maxActive)
	}
}

// attachKprobes attaches functions to their kprobles in provided module
func attachKprobes(module *bcc.Module, kprobes map[string]string) (map[string]uint64, error) {
	return attachSomething(module, module.LoadKprobe, withMaxActive(module.AttachKprobe, 0), kprobes)
}

// attachKretprobes attaches functions to their kretprobles in provided module
func attachKretprobes(module *bcc.Module, kretprobes map[string]string) (map[string]uint64, error) {
	return attachSomething(module, module.LoadKprobe, withMaxActive(module.AttachKretprobe, 0), kretprobes)
}

// attachTracepoints attaches functions to their tracepoints in provided module
func attachTracepoints(module *bcc.Module, tracepoints map[string]string) (map[string]uint64, error) {
	return attachSomething(module, module.LoadTracepoint, module.AttachTracepoint, tracepoints)
}

// attachRawTracepoints attaches functions to their tracepoints in provided module
func attachRawTracepoints(module *bcc.Module, tracepoints map[string]string) (map[string]uint64, error) {
	return attachSomething(module, module.LoadRawTracepoint, module.AttachRawTracepoint, tracepoints)
}
