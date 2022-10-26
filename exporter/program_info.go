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

const bpfStatsFile = "/proc/sys/kernel/bpf_stats_enabled"

type programInfo struct {
	id       int
	tag      string
	runTime  time.Duration
	runCount int
}

func extractProgramInfo(prog *libbpfgo.BPFProg) (programInfo, error) {
	info := programInfo{}

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

func bpfStatsEnabled() (bool, error) {
	f, err := os.Open(bpfStatsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}

		return false, fmt.Errorf("error opening %q: %v", bpfStatsFile, err)
	}

	defer f.Close()

	buf := make([]byte, 1)

	_, err = f.Read(buf)
	if err != nil {
		return false, fmt.Errorf("error reading %q: %v", bpfStatsFile, err)
	}

	// 0x31 is '1' in ascii
	return buf[0] == 0x31, nil
}
