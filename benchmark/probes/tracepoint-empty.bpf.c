#include "vmlinux.h"
#include <bpf/bpf_tracing.h>

SEC("tp_btf/sys_enter")
int BPF_PROG(probe)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
