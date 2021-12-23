# ebpf_exporter

Prometheus exporter for custom eBPF metrics.

Motivation of this exporter is to allow you to write eBPF code and export
metrics that are not otherwise accessible from the Linux kernel.

eBPF was [described by](https://lkml.org/lkml/2015/4/14/232) Ingo Molnár as:

> One of the more interesting features in this cycle is the ability to attach
> eBPF programs (user-defined, sandboxed bytecode executed by the kernel)
> to kprobes. This allows user-defined instrumentation on a live kernel image
> that can never crash, hang or interfere with the kernel negatively.

An easy way of thinking about this exporter is bcc tools as prometheus metrics:

* https://iovisor.github.io/bcc

## Reading material

* https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
* http://www.brendangregg.com/ebpf.html

## Building and running

### Note on bcc

`ebpf_exporter` depends on `libbcc` to instrument the kernel, and you need
to have it installed on your system. Please consule `bcc` documentation:

* https://github.com/iovisor/bcc/blob/master/INSTALL.md

Note that there's a dependency between `bcc` version you have on your system
and `gobpf`, which is Go's library to talk to `libbcc`. If you see errors
pointing to argument mismatch, it probably means that your `libbcc` version
doesn't match what `gobpf` expects. Currently `ebpf_exporter` works with `bcc`
0.22.0, but if you see issues with newer versions, please file an issue.

This setup also prevents us from providing prebuilt static binaries.

If you can figure out a way to statically link `bcc` into `ebpf_exporter`
to remove this nuisance, your contribution will be most welcome.

### Actual building

To build a binary from latest sources:

```
$ go get -u -v github.com/cloudflare/ebpf_exporter/...
```

To run with [`bio`](examples/bio.yaml) config (you need `root` privileges):

```
$ ~/go/bin/ebpf_exporter --config.file=src/github.com/cloudflare/ebpf_exporter/examples/bio.yaml
```

If you pass `--debug`, you can see raw tables at `/tables` endpoint.

### Docker image

There's a `Dockerfile` in repo root that builds both `bcc` and `ebpf_exporter`.
It's not intended for running, but rather to ensure that we have a predefined
build environment in which everything compiles successfully.

## Benchmarking overhead

See [benchmark](benchmark) directory to get an idea of how low ebpf overhead is.

## Supported scenarios

Currently the only supported way of getting data out of the kernel
is via maps (we call them tables in configuration). See:

* https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#maps

See [examples](#examples) section for real world examples.

If you have examples you want to share, please feel free to open a PR.

## Configuration

Skip to [format](#configuration-file-format) to see the full specification.

### Examples

You can find additional examples in [examples](examples) directory.

Unless otherwise specified, all examples are expected to work on Linux 4.14,
which is the latest LTS release at the time of writing.

In general, exported to work from Linux 4.1. See BCC docs for more details:

* https://github.com/iovisor/bcc/blob/master/INSTALL.md#kernel-configuration

#### Page cache operations for `syslog-ng` and `systemd-journald` (counters)

This program attaches to kernel functions responsible for managing
page cache and counts pages going through them.

This is an adapted version of `cachestat` from bcc tools:

* https://github.com/iovisor/bcc/blob/master/tools/cachestat_example.txt

Resulting metrics:

```
# HELP ebpf_exporter_page_cache_ops_total Page cache operation counters by type
# TYPE ebpf_exporter_page_cache_ops_total counter
ebpf_exporter_page_cache_ops_total{command="syslog-ng",op="account_page_dirtied"} 1531
ebpf_exporter_page_cache_ops_total{command="syslog-ng",op="add_to_page_cache_lru"} 1092
ebpf_exporter_page_cache_ops_total{command="syslog-ng",op="mark_buffer_dirty"} 31205
ebpf_exporter_page_cache_ops_total{command="syslog-ng",op="mark_page_accessed"} 54846
ebpf_exporter_page_cache_ops_total{command="systemd-journal",op="account_page_dirtied"} 104681
ebpf_exporter_page_cache_ops_total{command="systemd-journal",op="add_to_page_cache_lru"} 7330
ebpf_exporter_page_cache_ops_total{command="systemd-journal",op="mark_buffer_dirty"} 125486
ebpf_exporter_page_cache_ops_total{command="systemd-journal",op="mark_page_accessed"} 898214
```

You can check out `cachestat` source code to see how these translate:

* https://github.com/iovisor/bcc/blob/master/tools/cachestat.py

```yaml
programs:
  - name: cachestat
    metrics:
      counters:
        - name: page_cache_ops_total
          help: Page cache operation counters by type
          table: counts
          labels:
            - name: op
              size: 8
              decoders:
                - name: ksym
            - name: command
              size: 128
              decoders:
                - name: string
                - name: regexp
                  regexps:
                    - ^systemd-journal$
                    - ^syslog-ng$
    kprobes:
      add_to_page_cache_lru: do_count
      mark_page_accessed: do_count
      account_page_dirtied: do_count
      mark_buffer_dirty: do_count
    code: |
      #include <uapi/linux/ptrace.h>

      struct key_t {
          u64 ip;
          char command[128];
      };

      BPF_HASH(counts, struct key_t);

      int do_count(struct pt_regs *ctx) {
          struct key_t key = { .ip = PT_REGS_IP(ctx) - 1 };
          bpf_get_current_comm(&key.command, sizeof(key.command));

          counts.increment(key);

          return 0;
      }
```

#### Block IO histograms (histograms)

This program attaches to block io subsystem and reports metrics on disk
latency and request sizes for separate disks.

The following tools are working with similar concepts:

* https://github.com/iovisor/bcc/blob/master/tools/biosnoop_example.txt
* https://github.com/iovisor/bcc/blob/master/tools/biolatency_example.txt
* https://github.com/iovisor/bcc/blob/master/tools/bitesize_example.txt

This program was the initial reason for the exporter and was heavily
influenced by the experimental exporter from Daniel Swarbrick:

* https://github.com/dswarbrick/ebpf_exporter

Resulting metrics:

```
# HELP ebpf_exporter_bio_latency_seconds Block IO latency histogram
# TYPE ebpf_exporter_bio_latency_seconds histogram
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="1e-06"} 0
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="2e-06"} 0
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="4e-06"} 0
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="8e-06"} 0
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="1.6e-05"} 0
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="3.2e-05"} 0
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="6.4e-05"} 2
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="0.000128"} 388
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="0.000256"} 20086
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="0.000512"} 21601
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="0.001024"} 22487
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="0.002048"} 25592
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="0.004096"} 26891
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="0.008192"} 27835
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="0.016384"} 28540
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="0.032768"} 28725
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="0.065536"} 28776
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="0.131072"} 28786
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="0.262144"} 28790
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="0.524288"} 28792
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="1.048576"} 28792
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="2.097152"} 28792
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="4.194304"} 28792
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="8.388608"} 28792
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="16.777216"} 28792
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="33.554432"} 28792
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="67.108864"} 28792
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="read",le="+Inf"} 28792
ebpf_exporter_bio_latency_seconds_sum{device="sda",operation="read"} 0
ebpf_exporter_bio_latency_seconds_count{device="sda",operation="read"} 28792
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="1e-06"} 0
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="2e-06"} 0
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="4e-06"} 0
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="8e-06"} 0
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="1.6e-05"} 0
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="3.2e-05"} 508
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="6.4e-05"} 2828
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="0.000128"} 5701
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="0.000256"} 8520
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="0.000512"} 11975
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="0.001024"} 12448
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="0.002048"} 16798
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="0.004096"} 26909
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="0.008192"} 41248
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="0.016384"} 59030
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="0.032768"} 86501
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="0.065536"} 118934
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="0.131072"} 122148
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="0.262144"} 122373
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="0.524288"} 122462
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="1.048576"} 122470
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="2.097152"} 122470
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="4.194304"} 122470
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="8.388608"} 122470
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="16.777216"} 122470
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="33.554432"} 122470
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="67.108864"} 122470
ebpf_exporter_bio_latency_seconds_bucket{device="sda",operation="write",le="+Inf"} 122470
ebpf_exporter_bio_latency_seconds_sum{device="sda",operation="write"} 0
ebpf_exporter_bio_latency_seconds_count{device="sda",operation="write"} 122470
...
```

```
# HELP ebpf_exporter_bio_size_bytes Block IO size histogram with kibibyte buckets
# TYPE ebpf_exporter_bio_size_bytes histogram
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="read",le="1024"} 14
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="read",le="2048"} 14
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="read",le="4096"} 28778
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="read",le="8192"} 28778
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="read",le="16384"} 28778
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="read",le="32768"} 28778
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="read",le="65536"} 28779
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="read",le="131072"} 28781
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="read",le="262144"} 28785
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="read",le="524288"} 28792
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="read",le="1.048576e+06"} 28792
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="read",le="2.097152e+06"} 28792
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="read",le="4.194304e+06"} 28792
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="read",le="8.388608e+06"} 28792
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="read",le="1.6777216e+07"} 28792
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="read",le="3.3554432e+07"} 28792
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="read",le="+Inf"} 28792
ebpf_exporter_bio_size_bytes_sum{device="sda",operation="read"} 0
ebpf_exporter_bio_size_bytes_count{device="sda",operation="read"} 28792
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="write",le="1024"} 1507
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="write",le="2048"} 4007
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="write",le="4096"} 15902
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="write",le="8192"} 17726
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="write",le="16384"} 18429
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="write",le="32768"} 19639
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="write",le="65536"} 19676
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="write",le="131072"} 20367
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="write",le="262144"} 21952
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="write",le="524288"} 49636
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="write",le="1.048576e+06"} 122470
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="write",le="2.097152e+06"} 122470
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="write",le="4.194304e+06"} 122470
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="write",le="8.388608e+06"} 122470
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="write",le="1.6777216e+07"} 122470
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="write",le="3.3554432e+07"} 122470
ebpf_exporter_bio_size_bytes_bucket{device="sda",operation="write",le="+Inf"} 122470
ebpf_exporter_bio_size_bytes_sum{device="sda",operation="write"} 0
ebpf_exporter_bio_size_bytes_count{device="sda",operation="write"} 122470
...
```

To nicely plot these in Grafana, you'll need v5.1:

* https://github.com/grafana/grafana/pull/11087

![Histogram](examples/bio.write.latency.png)

```yaml
programs:
  # See:
  # * https://github.com/iovisor/bcc/blob/master/tools/biolatency.py
  # * https://github.com/iovisor/bcc/blob/master/tools/biolatency_example.txt
  #
  # See also: bio-tracepoints.yaml
  - name: bio
    metrics:
      histograms:
        - name: bio_latency_seconds
          help: Block IO latency histogram
          table: io_latency
          bucket_type: exp2
          bucket_min: 0
          bucket_max: 26
          bucket_multiplier: 0.000001 # microseconds to seconds
          labels:
            - name: device
              size: 32
              decoders:
                - name: string
            - name: operation
              size: 8
              decoders:
                - name: uint
                - name: static_map
                  static_map:
                    1: read
                    2: write
            - name: bucket
              size: 8
              decoders:
                - name: uint
        - name: bio_size_bytes
          help: Block IO size histogram with kibibyte buckets
          table: io_size
          bucket_type: exp2
          bucket_min: 0
          bucket_max: 15
          bucket_multiplier: 1024 # kibibytes to bytes
          labels:
            - name: device
              size: 32
              decoders:
                - name: string
            - name: operation
              size: 8
              decoders:
                - name: uint
                - name: static_map
                  static_map:
                    1: read
                    2: write
            - name: bucket
              size: 8
              decoders:
                - name: uint
    kprobes:
      blk_start_request: trace_req_start
      blk_mq_start_request: trace_req_start
      blk_account_io_completion: trace_req_completion
    code: |
      #include <linux/blkdev.h>
      #include <linux/blk_types.h>

      typedef struct disk_key {
          char disk[32];
          u8 op;
          u64 slot;
      } disk_key_t;

      // Max number of disks we expect to see on the host
      const u8 max_disks = 255;

      // 27 buckets for latency, max range is 33.6s .. 67.1s
      const u8 max_latency_slot = 26;

      // 16 buckets per disk in kib, max range is 16mib .. 32mib
      const u8 max_size_slot = 15;

      // Hash to temporily hold the start time of each bio request, max 10k in-flight by default
      BPF_HASH(start, struct request *);

      // Histograms to record latencies
      BPF_HISTOGRAM(io_latency, disk_key_t, (max_latency_slot + 2) * max_disks);

      // Histograms to record sizes
      BPF_HISTOGRAM(io_size, disk_key_t, (max_size_slot + 2) * max_disks);

      // Record start time of a request
      int trace_req_start(struct pt_regs *ctx, struct request *req) {
          u64 ts = bpf_ktime_get_ns();
          start.update(&req, &ts);

          return 0;
      }

      // Calculate request duration and store in appropriate histogram bucket
      int trace_req_completion(struct pt_regs *ctx, struct request *req, unsigned int bytes) {
          u64 *tsp, delta;

          // Fetch timestamp and calculate delta
          tsp = start.lookup(&req);
          if (tsp == 0) {
              return 0; // missed issue
          }

          // There are write request with zero length on sector zero,
          // which do not seem to be real writes to device.
          if (req->__sector == 0 && req->__data_len == 0) {
            return 0;
          }

          // Disk that received the request
          struct gendisk *disk = req->rq_disk;

          // Delta in nanoseconds
          delta = bpf_ktime_get_ns() - *tsp;

          // Convert to microseconds
          delta /= 1000;

          // Latency histogram key
          u64 latency_slot = bpf_log2l(delta);

          // Cap latency bucket at max value
          if (latency_slot > max_latency_slot) {
              latency_slot = max_latency_slot;
          }

          disk_key_t latency_key = { .slot = latency_slot };
          bpf_probe_read(&latency_key.disk, sizeof(latency_key.disk), &disk->disk_name);

          // Size in kibibytes
          u64 size_kib = bytes / 1024;

          // Request size histogram key
          u64 size_slot = bpf_log2(size_kib);

          // Cap latency bucket at max value
          if (size_slot > max_size_slot) {
              size_slot = max_size_slot;
          }

          disk_key_t size_key = { .slot = size_slot };
          bpf_probe_read(&size_key.disk, sizeof(size_key.disk), &disk->disk_name);

          if ((req->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE) {
              latency_key.op = 2;
              size_key.op    = 2;
          } else {
              latency_key.op = 1;
              size_key.op    = 1;
          }

          io_latency.increment(latency_key);
          io_size.increment(size_key);

          // Increment sum keys
          latency_key.slot = max_latency_slot + 1;
          io_latency.increment(latency_key, delta);
          size_key.slot = max_size_slot + 1;
          io_size.increment(size_key, size_kib);

          start.delete(&req);

          return 0;
      }
```

There is also a tracepoint based equivalent of this example in `examples`.

### Programs

Programs combine a piece of eBPF code running in the kernel with configuration
describing how to export collected data as prometheus metrics. There may
be multiple programs running from one exporter instance.

### Metrics

Metrics define what values we get from eBPF program running in the kernel.

#### Counters

Counters from maps are straightforward: you pull data out of kernel,
transform map keys into sets of labels and export them as prometheus counters.

#### Histograms

Histograms from maps are a bit more complex than counters. Maps in the kernel
cannot be nested, so we need to pack keys in the kernel and unpack in user space.

We get from this:

```
sda, read, 1ms -> 10 ops
sda, read, 2ms -> 25 ops
sda, read, 4ms -> 51 ops
```

To this:

```
sda, read -> [1ms -> 10 ops, 2ms -> 25 ops, 4ms -> 51 ops]
```

Prometheus histograms expect to have all buckets when we report a metric,
but the kernel creates keys as events occur, which means we need to backfill
the missing data.

That's why for histogram configuration we have the following keys:

* `bucket_type`: can be either `exp2`, `linear`, or `fixed`
* `bucket_min`: minimum bucket key (`exp2` and `linear` only)
* `bucket_max`: maximum bucket key (`exp2` and `linear` only)
* `bucket_keys`: maximum bucket key (`fixed` only)
* `bucket_multiplier`: multiplier for bucket keys (default is `1`)

##### `exp2` histograms

For `exp2` histograms we expect kernel to provide a map with linear keys that
are log2 of actual values. We then go from `bucket_min` to `bucket_max` in
user space and remap keys by exponentiating them:

```
count = 0
for i = bucket_min; i < bucket_max; i++ {
  count += map.get(i, 0)
  result[exp2(i) * bucket_multiplier] = count
}
```

Here `map` is the map from the kernel and `result` is what goes to prometheus.

We take cumulative `count`, because this is what prometheus expects.

##### `linear` histograms

For `linear` histograms we expect kernel to provide a map with linear keys
that are results of integer division of original value by `bucket_multiplier`.
To reconstruct the histogram in user space we do the following:

```
count = 0
for i = bucket_min; i < bucket_max; i++ {
  count += map.get(i, 0)
  result[i * bucket_multiplier] = count
}
```

##### `fixed` histograms

For `fixed` histograms we expect kernel to provide a map with fixed keys
defined by the user.

```
count = 0
for i = 0; i < len(bucket_keys); i++ {
  count  += map.get(bucket_keys[i], 0)
  result[bucket_keys[i] * multiplier] = count
}
```

##### `sum` keys

For `exp2` and `linear` hisograms, if `bucket_max + 1` contains a non-zero
value, it will be used as a `sum` key in histogram, providing additional
information.

For `fixed` histograms, if `buckets_keys[len(bucket_keys) -1 ] + 1` contains
a non-zero value, it will be used as a `sum` key.

##### Advice on values outside of `[bucket_min, bucket_max]`

For both `exp2` and `linear` histograms it is important that kernel does
not count events into buckets outside of `[bucket_min, bucket_max]` range.
If you encounter a value above your range, truncate it to be in it. You're
losing `+Inf` bucket, but usually it's not that big of a deal.

Each kernel map key must count values under that key's value to match
the behavior of prometheus. For example, `exp2` histogram key `3` should
count values for `(exp2(2), exp2(3)]` interval: `(4, 8]`. To put it simply:
use `bpf_log2l` or integer division and you'll be good.

The side effect of implementing histograms this way is that some granularity
is lost due to either taking `log2` or division. We explicitly set `_sum` key
of prometheus histogram to zero to avoid confusion around this.

### Labels

Labels transform kernel map keys into prometheus labels.

Maps coming from the kernel are binary encoded. Values are always `u64`, but
keys can be primitive types like `u64` or structs.

Each label can be transformed with decoders (see below) according to metric
configuration. Generally number of labels matches number of elements
in the kernel map key.

For map keys that are represented as structs alignment rules apply:

* `u64` must be aligned at 8 byte boundary
* `u32` must be aligned at 4 byte boundary
* `u16` must be aligned at 2 byte boundary

This means that the following struct:

```c
typedef struct disk_key {
    char disk[32];
    u8 op;
    u64 slot;
} disk_key_t;
```

Is represented as:

* 32 byte `disk` char array
* 1 byte `op` integer
* 7 byte padding to align `slot`
* 8 byte `slot` integer

When decoding, label sizes should be supplied with padding included:

* 32 for `disk`
* 8 for `op` (1 byte value + 7 byte padding)
* 8 byte `slot`

### Decoders

Decoders take a byte slice input of requested length and transform it into
a byte slice representing a string. That byte slice can either be consumed
by another decoder (for example `string` -> `regexp`) or or used as the final
label value exporter to Prometheus.

Below are decoders we have built in.

#### `ksym`

KSym decoder takes kernel address and converts that to the function name.

In your eBPF program you can use `PT_REGS_IP(ctx)` to get the address
of the kprobe you attached to as a `u64` variable. Note that sometimes
you can observe `PT_REGS_IP` being off by one. You can subtract 1 in your code
to make it point to the right instruction that can be found `/proc/kallsyms`.

#### `regexp`

Regexp decoder takes list of strings from `regexp` configuration key
of the decoder and ties to use each as a pattern in `golang.org/pkg/regexp`:

* https://golang.org/pkg/regexp

If decoder input matches any of the patterns, it is permitted.
Otherwise, the whole metric label set is dropped.

An example to report metrics only for `systemd-journal` and `syslog-ng`:

```
- name: command
  decoders:
    - name: string
    - name: regexp
      regexps:
        - ^systemd-journal$
        - ^syslog-ng$
```

#### `static_map`

Static map decoder takes input and maps it to another value via `static_map`
configuration key of the decoder. Values are expected as strings.

An example to match `1` to `read` and `2` to `write`:

```
- name: operation
  decoders:
    - name:static_map
      static_map:
        1: read
        2: write
```
Unkown keys will be replaced by `"unknown:key_name"` unless `allow_unknown: true`
is specified in the decoder. For example, the above will decode `3` to `unknown:3`
and the below example will decode `3` to `3`:

```
- name: operation
  decoders:
    - name:static_map
      allow_unknown: true
      static_map:
        1: read
        2: write
```


#### `string`

String decoder transforms possibly null terminated strings coming
from the kernel into string usable for prometheus metrics.

#### `dname`

Dname decoder read DNS qname from string in wire format, then decode
it into '.' notation format. Could be used after `string` decoder.
E.g.: `\x07example\03com\x00` will become `example.com`. This decoder
could be used after `string` decode, like the following example:

```
- name: qname
  decoders:
    - name: string
	- name: dname
```

#### `uint`

UInt decoder transforms hex encoded `uint` values from the kernel
into regular numbers. For example: `0xe -> 14`.

### Configuration file format

Configuration file is defined like this:

```
# List of eBPF programs to run
- programs:
  [ - <program> ]
```

#### `program`

See [Programs](#programs) section for more details.

```
# Program name
name: <program name>
# Metrics attached to the program
[ metrics: metrics ]
# Kprobes (kernel functions) and their targets (eBPF functions)
kprobes:
  [ kprobename: target ... ]
# Kretprobes (kernel functions) and their targets (eBPF functions)
kretprobes:
  [ kprobename: target ... ]
# Tracepoints (category:name, i.e. timer:timer_start) and their targets (eBPF functions)
tracepoints:
  [ tracepoint: target ... ]
# Raw tracepoints (name, i.e. timer_start) and their targets (eBPF functions)
raw_tracepoints:
  [ tracepoint: target ... ]
# Perf events configuration
perf_events:
  [ - perf_event ]
# Cflags are passed to the bcc compiler, useful for preprocessing
cflags:
  [ - -I/include/path
    - -DMACRO_NAME=value ]
# Kernel symbol addresses to define as kaddr_{symbol} from /proc/kallsyms (consider CONFIG_KALLSYMS_ALL)
kaddrs:
  [ - symbol_to_resolve ]
# Actual eBPF program code to inject in the kernel
code: [ code ]
```

#### `perf_event`

See [llcstat](examples/llcstat.yaml) as an example.

```
- type: [ perf event type code ]
  name: [ perf event name code ]
  target: [ target eBPF function ]
  sample_period: [ sample period ]
  sample_frequency: [ sample frequency ]
```

It's preferred to use `sample_frequency` to let kernel pick the sample period
automatically, otherwise you may end up with invalid metrics on overflow.

#### `metrics`

See [Metrics](#metrics) section for more details.

```
counters:
  [ - counter ]
histograms:
  [ - histogram ]
```

#### `counter`

See [Counters](#counters) section for more details.

```
name: <prometheus counter name>
help: <prometheus metric help>
table: <eBPF table name to track>
perf_map: <name for a BPF_PERF_OUTPUT map> # optional
perf_map_flush_duration: <how often should we flush metrics from perf_map: time.Duration> # optional
labels:
  [ - label ]
```

An example of `perf_map` can be found [here](examples/oomkill.yaml).

#### `histogram`

See [Histograms](#histograms) section for more details.

```
name: <prometheus histogram name>
help: <prometheus metric help>
table: <eBPF table name to track>
bucket_type: <table bucket type: exp2 or linear>
bucket_multiplier: <table bucket multiplier: float64>
bucket_min: <min bucket value: int>
bucket_max: <max bucket value: int>
labels:
  [ - label ]
```

#### `label`

See [Labels](#labels) section for more details.

```
name: <prometheus label name>
size: <field size with padding>
decoders:
  [ - decoder ]
```

#### `decoder`

See [Decoders](#decoders) section for more details.

```
name: <decoder name>
# ... decoder specific configuration
```

## Built-in metrics

### `ebpf_exporter_enabled_programs`

This gauge reports a timeseries for every loaded logical program:

```
# HELP ebpf_exporter_enabled_programs The set of enabled programs
# TYPE ebpf_exporter_enabled_programs gauge
ebpf_exporter_enabled_programs{name="xfs_reclaim"} 1
```

### `ebpf_exporter_ebpf_programs`

This gauge reports information available for every ebpf program:

```
# HELP ebpf_exporter_ebpf_programs Info about ebpf programs
# TYPE ebpf_exporter_ebpf_programs gauge
ebpf_exporter_ebpf_programs{function="xfs_fs_free_cached_objects_end",program="xfs_reclaim",tag="d5e845dc27b372e4"} 1
ebpf_exporter_ebpf_programs{function="xfs_fs_free_cached_objects_start",program="xfs_reclaim",tag="c2439d02dd0ba000"} 1
ebpf_exporter_ebpf_programs{function="xfs_fs_nr_cached_objects_end",program="xfs_reclaim",tag="598375893f34ef39"} 1
ebpf_exporter_ebpf_programs{function="xfs_fs_nr_cached_objects_start",program="xfs_reclaim",tag="cf30348184f983dd"} 1
```

Here `tag` can be used for tracing and performance analysis with two conditions:

* `net.core.bpf_jit_kallsyms=1` sysctl is set
* `--kallsyms=/proc/kallsyms` is passed to `perf record`

Newer kernels allow `--kallsyms` to `perf top` as well,
in the future it may not be required at all:

* https://www.spinics.net/lists/linux-perf-users/msg07216.html

## License

MIT
