package exporter

import (
	"fmt"

	"github.com/elastic/go-perf"
	"github.com/iovisor/gobpf/pkg/cpuonline"
	"golang.org/x/sys/unix"
)

// EnableLBR configures a perf event that enables LBR
func EnableLBR() error {
	attr := &perf.Attr{}
	attr.Type = perf.HardwareEvent
	attr.Config = unix.PERF_COUNT_HW_CPU_CYCLES
	attr.SampleFormat = perf.SampleFormat{BranchStack: true}
	attr.BranchSampleFormat = perf.BranchSampleFormat{Privilege: perf.BranchPrivilegeKernel, Sample: perf.BranchSampleAnyReturn}

	cpus, err := cpuonline.Get()
	if err != nil {
		return fmt.Errorf("failed to determine online cpus: %w", err)
	}

	for _, cpu := range cpus {
		_, err := perf.Open(attr, perf.AllThreads, int(cpu), nil)
		if err != nil {
			return fmt.Errorf("failed to open perf_event: %w", err)
		}
	}

	return nil
}
