package exporter

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/config"
	"github.com/elastic/go-perf"
	"github.com/iovisor/gobpf/pkg/cpuonline"
)

const progTagPrefix = "prog_tag:\t"

func attachModule(module *libbpfgo.Module, program config.Program) (map[string]string, error) {
	tags := map[string]string{}

	iter := module.Iterator()
	for {
		prog := iter.NextProgram()
		if prog == nil {
			break
		}

		// We attach perf events separately
		if prog.GetType() == libbpfgo.BPFProgTypePerfEvent {
			continue
		}

		name := prog.Name()

		tag, err := extractTag(prog)
		if err != nil {
			return nil, fmt.Errorf("failed to get program tag for for program %q: %v", name, err)
		}

		tags[name] = tag

		_, err = prog.AttachGeneric()
		if err != nil {
			return nil, fmt.Errorf("failed to attach program %q: %v", name, err)
		}
	}

	perfEventProgramTags, err := attachPerfEvents(module, program)
	if err != nil {
		return nil, fmt.Errorf("failed to attach perf event tags: %v", err)
	}

	for key, value := range perfEventProgramTags {
		tags[key] = value
	}

	return tags, nil
}

func attachPerfEvents(module *libbpfgo.Module, program config.Program) (map[string]string, error) {
	tags := map[string]string{}

	for _, perfEventConfig := range program.PerfEvents {
		prog, err := module.GetProgram(perfEventConfig.Target)
		if err != nil {
			return nil, fmt.Errorf("failed to load target %q in program %q: %s", perfEventConfig.Target, program.Name, err)
		}

		fa := &perf.Attr{
			Type:   perf.EventType(perfEventConfig.Type),
			Config: perfEventConfig.Name,
		}

		if perfEventConfig.SampleFrequency != 0 {
			fa.SetSampleFreq(perfEventConfig.SampleFrequency)
		} else {
			fa.SetSamplePeriod(perfEventConfig.SamplePeriod)
		}

		cpus, err := cpuonline.Get()
		if err != nil {
			return nil, fmt.Errorf("failed to determine online cpus: %v", err)
		}

		name := prog.Name()

		for _, cpu := range cpus {
			event, err := perf.Open(fa, perf.AllThreads, int(cpu), nil)
			if err != nil {
				return nil, fmt.Errorf("failed to open perf_event: %v", err)
			}

			fd, err := event.FD()
			if err != nil {
				return nil, fmt.Errorf("failed to get perf_event fd: %v", err)
			}

			_, err = prog.AttachPerfEvent(fd)
			if err != nil {
				return nil, fmt.Errorf("failed to attach perf event %d:%d to %q in program %q on cpu %d: %s", perfEventConfig.Type, perfEventConfig.Name, perfEventConfig.Target, name, cpu, err)
			}
		}

		tag, err := extractTag(prog)
		if err != nil {
			return nil, fmt.Errorf("failed to get program tag for for program %q: %v", name, err)
		}

		tags[name] = tag
	}

	return tags, nil
}

func extractTag(prog *libbpfgo.BPFProg) (string, error) {
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
