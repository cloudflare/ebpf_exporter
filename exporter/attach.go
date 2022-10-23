package exporter

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/config"
)

const progTagPrefix = "prog_tag:\t"

func attachModule(module *libbpfgo.Module, program config.Program) ([]progAttachment, error) {
	attachments := []progAttachment{}

	iter := module.Iterator()
	for {
		prog := iter.NextProgram()
		if prog == nil {
			break
		}

		name := prog.Name()

		tag, err := extractTag(prog)
		if err != nil {
			return nil, fmt.Errorf("failed to get program tag for for program %q: %v", name, err)
		}

		attachment := progAttachment{
			name: name,
			tag:  tag,
		}

		_, err = prog.AttachGeneric()
		if err != nil {
			log.Printf("Failed to attach program %q for %q: %v", name, program.Name, err)
		} else {
			attachment.attached = true
		}

		attachments = append(attachments, attachment)
	}

	return attachments, nil
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

type progAttachment struct {
	name     string
	tag      string
	attached bool
}
