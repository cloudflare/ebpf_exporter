#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#if defined(__TARGET_ARCH_x86)
SEC("fentry/__x64_sys_getpid")
#elif defined(__TARGET_ARCH_arm64)
SEC("fentry/__arm64_sys_getpid")
#else
#error Unknown target for this architecture
#endif
int probe(struct pt_regs *ctx)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
