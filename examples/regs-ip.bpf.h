// for kprobes, entry is function IP + sizeof(kprobe_opcode_t),
// subtract in BPF prog context to get fn address.
//
// See: https://github.com/iovisor/bcc/blob/v0.25.0/libbpf-tools/ksnoop.h#L52-L59

#ifdef __TARGET_ARCH_x86
#define KPROBE_REGS_IP_FIX(ip) (ip - sizeof(kprobe_opcode_t))
#else
#define KPROBE_REGS_IP_FIX(ip) ip
#endif
