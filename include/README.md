# `vmlinux.h`

This file is synthesized by `bpftool` from BTF information in the kernel.
Most of it is arch independent, but some bits like registers depend on
the target architecture, so it's easiest to make it per architecture.

The files here were generated from Ubuntu 22.04 and Linux 5.15 kernel:

* https://bugs.launchpad.net/ubuntu/jammy/+package/linux-image-unsigned-5.15.0-25-generic-dbgsym

To regenerate the files, download both amd64 and arm64 ddbg files from above,
then run the following command on each to get the `vmlinux.h` contents:

```
rm -rf /tmp/ddbg
mkdir /tmp/ddbg
dpkg-deb -x linux-image-unsigned-5.15.0-25-generic-dbgsym_5.15.0-25.25_arm64.ddeb /tmp/ddbg/
sudo bpftool btf dump file /tmp/ddbg/usr/lib/debug/boot/vmlinux-5.15.0-25-generic format c
```

For more information see `libbpf-bootstrap` documentation:

* https://nakryiko.com/posts/libbpf-bootstrap/#includes-vmlinux-h-libbpf-and-app-headers
