# `vmlinux.h`

This file is synthesized by `bpftool` from BTF information in the kernel.

To regenerate it use the following command:

```
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

For more information see `libbpf-bootstrap` documentation:

* https://nakryiko.com/posts/libbpf-bootstrap/#includes-vmlinux-h-libbpf-and-app-headers
