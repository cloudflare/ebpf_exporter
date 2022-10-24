package exporter

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/libbpfgo"
)

type progInfo struct {
	id       int
	tag      string
	runTime  time.Duration
	runCount int
}

func extractProgInfo(prog *libbpfgo.BPFProg) (progInfo, error) {
	info := progInfo{}

	name := fmt.Sprintf("/proc/self/fdinfo/%d", prog.FileDescriptor())

	file, err := os.Open(name)
	if err != nil {
		return info, fmt.Errorf("can't open %s: %v", name, err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())

		switch fields[0] {
		case "prog_tag:":
			info.tag = fields[1]
		case "prog_id:":
			info.id, err = strconv.Atoi(fields[1])
			if err != nil {
				return info, fmt.Errorf("error parsing prog id %q as int: %v", fields[1], err)
			}
		case "run_time_ns:":
			runTimeNs, err := strconv.Atoi(fields[1])
			if err != nil {
				return info, fmt.Errorf("error parsing prog run time duration %q as int: %v", fields[1], err)
			}
			info.runTime = time.Nanosecond * time.Duration(runTimeNs)
		case "run_cnt:":
			info.runCount, err = strconv.Atoi(fields[1])
			if err != nil {
				return info, fmt.Errorf("error parsing prog run count %q as int: %v", fields[1], err)
			}
		}
	}

	if err = scanner.Err(); err != nil {
		return info, fmt.Errorf("error scanning: %v", err)
	}

	return info, nil
}
