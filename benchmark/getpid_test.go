package benchmark

import (
	"fmt"
	"os"
	"testing"

	"github.com/iovisor/gobpf/bcc"
)

var simpleMapProbe = `
#include <uapi/linux/ptrace.h>

BPF_HASH(counts, u64);

int probe(struct pt_regs *ctx) {
    counts.increment(bpf_get_current_pid_tgid());
    return 0;
}
`

var complexMapProbe = `
#include <uapi/linux/ptrace.h>

struct key_t {
    u64 pid;
    u64 random;
    char command[32];
};

BPF_HASH(counts, struct key_t, u64, 100000);

int probe(struct pt_regs *ctx) {
    struct key_t key = {};

    key.pid = bpf_get_current_pid_tgid();
    key.random = bpf_ktime_get_ns() % 10000;
    bpf_get_current_comm(&key.command, sizeof(key.command));

    counts.increment(key);

    return 0;
}
`

func BenchmarkGetpid(b *testing.B) {
	for n := 0; n < b.N; n++ {
		os.Getpid()
	}
}

func BenchmarkGetpidWithSimpleMap(b *testing.B) {
	benchmarkWithProbe(b, simpleMapProbe)
}

func BenchmarkGetpidWithComplexMap(b *testing.B) {
	benchmarkWithProbe(b, complexMapProbe)
}

func benchmarkWithProbe(b *testing.B, text string) {
	m, err := setupGetpidProbe(text)
	if err != nil {
		b.Fatalf("Error setting up getpid probe: %s", err)
	}

	defer m.Close()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		os.Getpid()
	}
}

func setupGetpidProbe(text string) (*bcc.Module, error) {
	module := bcc.NewModule(text, []string{})
	if module == nil {
		return nil, fmt.Errorf("error compiling bcc module")
	}

	target, err := module.LoadKprobe("probe")
	if err != nil {
		return nil, fmt.Errorf("failed to load target: %s", err)
	}

	err = module.AttachKprobe("sys_getpid", target, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to attach kprobe: %s", err)
	}

	return module, nil
}
