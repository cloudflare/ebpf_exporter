# `vmlinux.h`

This file is synthesized by `bpftool` from BTF information in the kernel.
Most of it is arch independent, but some bits like registers depend on
the target architecture, so it's easiest to make it per architecture.

The files here were generated from Debian Bookworm `bpftool` (`7.1.0+6.1.124-1`)
and Linux v6.12 (`6.12.0-10-generic`) kernel packages from Ubuntu:

* https://launchpad.net/ubuntu/+source/linux

To regenerate the files, download both amd64 and arm64 ddbg files from above,
then run the following command on each to get the `vmlinux.h` contents:

```
rm -rf /tmp/ddbg
mkdir /tmp/ddbg
dpkg-deb -x linux-image-unsigned-6.12.0-10-generic-dbgsym_6.12.0-10.10_amd64.ddeb /tmp/ddbg/
sudo bpftool btf dump file /tmp/ddbg/usr/lib/debug/boot/vmlinux-6.12.0-10-generic format c
```

For more information see `libbpf-bootstrap` documentation:

* https://nakryiko.com/posts/libbpf-bootstrap/#includes-vmlinux-h-libbpf-and-app-headers
