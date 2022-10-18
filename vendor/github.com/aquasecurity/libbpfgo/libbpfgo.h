#ifndef __LIBBPF_GO_H__
#define __LIBBPF_GO_H__

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                    va_list args) {
  if (level != LIBBPF_WARN)
    return 0;

  // NOTE: va_list args is managed in libbpf caller
  // however, these copies must be matched with va_end() in this function
  va_list exclusivity_check, cgroup_check;
  va_copy(exclusivity_check, args);
  va_copy(cgroup_check, args);

  // BUG: https://github.com/aquasecurity/tracee/issues/1676

  char *str = va_arg(exclusivity_check, char *);
  if (strstr(str, "Exclusivity flag on") != NULL) {
    va_end(exclusivity_check);
    return 0;
  }
  va_end(exclusivity_check);

  // AttachCgroupLegacy() will first try AttachCgroup() and it
  // might fail. This is not an error and is the best way of
  // probing for eBPF cgroup attachment link existence.

  str = va_arg(cgroup_check, char *);
  if (strstr(str, "cgroup") != NULL) {
    str = va_arg(cgroup_check, char *);
    if (strstr(str, "Invalid argument") != NULL) {
      va_end(cgroup_check);
      return 0;
    }
  }
  va_end(cgroup_check);

  return vfprintf(stderr, format, args);
}

void set_print_fn() { libbpf_set_print(libbpf_print_fn); }

extern void perfCallback(void *ctx, int cpu, void *data, __u32 size);
extern void perfLostCallback(void *ctx, int cpu, __u64 cnt);
extern int ringbufferCallback(void *ctx, void *data, size_t size);

struct ring_buffer *init_ring_buf(int map_fd, uintptr_t ctx) {
  struct ring_buffer *rb = NULL;

  rb = ring_buffer__new(map_fd, ringbufferCallback, (void *)ctx, NULL);
  if (!rb) {
    int saved_errno = errno;
    fprintf(stderr, "Failed to initialize ring buffer: %s\n", strerror(errno));
    errno = saved_errno;
    return NULL;
  }

  return rb;
}

struct perf_buffer *init_perf_buf(int map_fd, int page_cnt, uintptr_t ctx) {
  struct perf_buffer_opts pb_opts = {};
  struct perf_buffer *pb = NULL;

  pb_opts.sz = sizeof(struct perf_buffer_opts);

  pb = perf_buffer__new(map_fd, page_cnt, perfCallback, perfLostCallback,
                        (void *)ctx, &pb_opts);
  if (!pb) {
    int saved_errno = errno;
    fprintf(stderr, "Failed to initialize perf buffer: %s\n", strerror(errno));
    errno = saved_errno;
    return NULL;
  }

  return pb;
}

void get_internal_map_init_value(struct bpf_map *map, void *value) {
  size_t psize;
  const void *data;
  data = bpf_map__initial_value(map, &psize);
  memcpy(value, data, psize);
}

int bpf_prog_attach_cgroup_legacy(
    int prog_fd,   // eBPF program file descriptor
    int target_fd, // cgroup directory file descriptor
    int type)      // BPF_CGROUP_INET_{INGRESS,EGRESS}, ...
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.target_fd = target_fd;
  attr.attach_bpf_fd = prog_fd;
  attr.attach_type = type;
  attr.attach_flags = BPF_F_ALLOW_MULTI; // or BPF_F_ALLOW_OVERRIDE

  return syscall(__NR_bpf, BPF_PROG_ATTACH, &attr, sizeof(attr));
}

int bpf_prog_detach_cgroup_legacy(
    int prog_fd,   // eBPF program file descriptor
    int target_fd, // cgroup directory file descriptor
    int type)      // BPF_CGROUP_INET_{INGRESS,EGRESS}, ...
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.target_fd = target_fd;
  attr.attach_bpf_fd = prog_fd;
  attr.attach_type = type;

  return syscall(__NR_bpf, BPF_PROG_DETACH, &attr, sizeof(attr));
}

struct bpf_object *open_bpf_object(char *btf_file_path, char *kconfig_path,
                                   char *bpf_obj_name, const void *obj_buf,
                                   size_t obj_buf_size) {
  struct bpf_object_open_opts opts = {};
  opts.btf_custom_path = btf_file_path;
  opts.kconfig = kconfig_path;
  opts.object_name = bpf_obj_name;
  opts.sz = sizeof(opts);

  struct bpf_object *obj = bpf_object__open_mem(obj_buf, obj_buf_size, &opts);
  if (obj == NULL) {
    int saved_errno = errno;
    fprintf(stderr, "Failed to open bpf object: %s\n", strerror(errno));
    errno = saved_errno;
    return NULL;
  }

  return obj;
}

#endif
