package exporter

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	bpf "github.com/aquasecurity/libbpfgo"
)

const progTagPrefix = "prog_tag:\t"

// mergeTags runs attacher and merges produced tags
func mergedTags(dst map[string]string, src map[string]string) {
	for name, tag := range src {
		dst[name] = tag
	}
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

	for probe, progName := range probes {
		prog, err := module.GetProgram(progName)
		if err != nil {
			return nil, fmt.Errorf("failed to load program %q: %v", progName, err)
		}

		tag, err := extractTag(prog)
		if err != nil {
			return nil, fmt.Errorf("failed to get program tag for for program %q: %v", progName, err)
		}

		tags[progName] = tag

		switch key {
		case "kprobe":
			_, err = prog.AttachKprobe(probe)
		case "kretprobe":
			_, err = prog.AttachKretprobe(probe)
		case "tracepoint":
			parts := strings.Split(probe, ":")
			if len(parts) != 2 {
				return nil, fmt.Errorf("tracepoint must be in 'category:name' format")
			}
			_, err = prog.AttachTracepoint(parts[0], parts[1])
		case "rawtracepoint":
			_, err = prog.AttachRawTracepoint(probe)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to attach probe %q to program %q: %v", progName, probe, err)
		}
	}

	return tags, nil
}

func extractTag(prog *bpf.BPFProg) (string, error) {
	name := fmt.Sprintf("/proc/self/fdinfo/%d", prog.FileDescriptor())

	file, err := os.Open(name)
	if err != nil {
		return "", fmt.Errorf("can't open %s: %v", name, err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, progTagPrefix) {
			return strings.TrimPrefix(line, progTagPrefix), nil
		}
	}

	if err = scanner.Err(); err != nil {
		return "", fmt.Errorf("error scanning: %v", err)
	}

	return "", errors.New("cannot find program tag")
}
