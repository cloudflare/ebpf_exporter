#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

struct pci_key_t {
    u32 vendor;
    u32 device;
    u8 class;
    u16 subclass;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 128);
    __type(key, struct pci_key_t);
    __type(value, u64);
} pci_user_read_config_ops_total SEC(".maps");

static int handle(struct pci_dev *dev)
{
    u16 vendor = BPF_CORE_READ(dev, vendor);
    u16 device = BPF_CORE_READ(dev, device);
    u32 class = BPF_CORE_READ(dev, class);

    struct pci_key_t key = {
        .vendor = vendor, .device = (vendor << 16) + device, .class = class >> 16, .subclass = class >> 8
    };

    increment_map(&pci_user_read_config_ops_total, &key, 1);

    return 0;
}

SEC("kprobe/pci_user_read_config_byte")
int BPF_PROG(pci_user_read_config_byte, struct pci_dev *dev)
{
    return handle(dev);
}

SEC("kprobe/pci_user_read_config_word")
int BPF_PROG(pci_user_read_config_word, struct pci_dev *dev)
{
    return handle(dev);
}

SEC("kprobe/pci_user_read_config_dword")
int BPF_PROG(pci_user_read_config_dword, struct pci_dev *dev)
{
    return handle(dev);
}

char LICENSE[] SEC("license") = "GPL";
