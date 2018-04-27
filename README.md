# ebpf_exporter

[![Build Status](https://travis-ci.org/cloudflare/ebpf_exporter.svg?branch=master)](https://travis-ci.org/cloudflare/ebpf_exporter)

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

To build, you need to have `libbcc` installed:

* https://github.com/iovisor/bcc/blob/master/INSTALL.md

```
$ mkdir /tmp/ebpf_exporter
$ cd /tmp/ebpf_exporter
$ GOPATH=$(pwd) go get -v github.com/cloudflare/ebpf_exporter/...
```

To run with [`bio`](examples/bio.yaml) config (you need `root` privileges):

```
$ ./bin/ebpf_exporter --config.file=src/github.com/cloudflare/ebpf_exporter/examples/bio.yaml
```

If you pass `--debug`, you can see raw tables at `/tables` endpoint.

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
# HELP ebpf_exporter_page_cache_ops Page cache operation counters by type
# TYPE ebpf_exporter_page_cache_ops counter
ebpf_exporter_page_cache_ops{command="syslog-ng",op="account_page_dirtied"} 1531
ebpf_exporter_page_cache_ops{command="syslog-ng",op="add_to_page_cache_lru"} 1092
ebpf_exporter_page_cache_ops{command="syslog-ng",op="mark_buffer_dirty"} 31205
ebpf_exporter_page_cache_ops{command="syslog-ng",op="mark_page_accessed"} 54846
ebpf_exporter_page_cache_ops{command="systemd-journal",op="account_page_dirtied"} 104681
ebpf_exporter_page_cache_ops{command="systemd-journal",op="add_to_page_cache_lru"} 7330
ebpf_exporter_page_cache_ops{command="systemd-journal",op="mark_buffer_dirty"} 125486
ebpf_exporter_page_cache_ops{command="systemd-journal",op="mark_page_accessed"} 898214
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
              decoders:
                - name: ksym
            - name: command
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
          struct key_t key = { .ip = PT_REGS_IP(ctx) };

          bpf_get_current_comm(&key.command, sizeof(key.command));

          u64 zero = 0, *val;
          val = counts.lookup_or_init(&key, &zero);
          (*val)++;

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
# HELP ebpf_exporter_bio_latency Block IO latency histogram with microsecond buckets
# TYPE ebpf_exporter_bio_latency histogram
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="1"} 0
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="2"} 0
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="4"} 0
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="8"} 0
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="16"} 0
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="32"} 0
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="64"} 0
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="128"} 0
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="256"} 135
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="512"} 203
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="1024"} 264
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="2048"} 318
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="4096"} 366
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="8192"} 381
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="16384"} 392
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="32768"} 397
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="65536"} 398
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="131072"} 398
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="262144"} 398
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="524288"} 398
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="1.048576e+06"} 398
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="2.097152e+06"} 398
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="4.194304e+06"} 398
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="8.388608e+06"} 398
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="1.6777216e+07"} 398
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="3.3554432e+07"} 398
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="6.7108864e+07"} 398
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="1.34217728e+08"} 398
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="2.68435456e+08"} 398
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="5.36870912e+08"} 398
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="1.073741824e+09"} 398
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="2.147483648e+09"} 398
ebpf_exporter_bio_latency_bucket{device="sda",operation="read",le="+Inf"} 398
ebpf_exporter_bio_latency_sum{device="sda",operation="read"} 0
ebpf_exporter_bio_latency_count{device="sda",operation="read"} 398
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="1"} 0
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="2"} 0
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="4"} 0
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="8"} 0
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="16"} 0
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="32"} 6
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="64"} 43
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="128"} 108
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="256"} 150
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="512"} 207
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="1024"} 225
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="2048"} 292
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="4096"} 489
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="8192"} 685
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="16384"} 837
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="32768"} 951
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="65536"} 1001
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="131072"} 1014
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="262144"} 1014
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="524288"} 1014
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="1.048576e+06"} 1014
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="2.097152e+06"} 1014
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="4.194304e+06"} 1014
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="8.388608e+06"} 1014
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="1.6777216e+07"} 1014
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="3.3554432e+07"} 1014
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="6.7108864e+07"} 1014
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="1.34217728e+08"} 1014
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="2.68435456e+08"} 1014
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="5.36870912e+08"} 1014
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="1.073741824e+09"} 1014
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="2.147483648e+09"} 1014
ebpf_exporter_bio_latency_bucket{device="sda",operation="write",le="+Inf"} 1014
ebpf_exporter_bio_latency_sum{device="sda",operation="write"} 0
ebpf_exporter_bio_latency_count{device="sda",operation="write"} 1014
...
```

```
# HELP ebpf_exporter_bio_size Block IO size histogram with kibibyte buckets
# TYPE ebpf_exporter_bio_size histogram
ebpf_exporter_bio_size_bucket{device="sda",operation="read",le="1"} 0
ebpf_exporter_bio_size_bucket{device="sda",operation="read",le="2"} 0
ebpf_exporter_bio_size_bucket{device="sda",operation="read",le="4"} 398
ebpf_exporter_bio_size_bucket{device="sda",operation="read",le="8"} 398
ebpf_exporter_bio_size_bucket{device="sda",operation="read",le="16"} 398
ebpf_exporter_bio_size_bucket{device="sda",operation="read",le="32"} 398
ebpf_exporter_bio_size_bucket{device="sda",operation="read",le="64"} 398
ebpf_exporter_bio_size_bucket{device="sda",operation="read",le="128"} 398
ebpf_exporter_bio_size_bucket{device="sda",operation="read",le="256"} 398
ebpf_exporter_bio_size_bucket{device="sda",operation="read",le="512"} 398
ebpf_exporter_bio_size_bucket{device="sda",operation="read",le="1024"} 398
ebpf_exporter_bio_size_bucket{device="sda",operation="read",le="2048"} 398
ebpf_exporter_bio_size_bucket{device="sda",operation="read",le="4096"} 398
ebpf_exporter_bio_size_bucket{device="sda",operation="read",le="8192"} 398
ebpf_exporter_bio_size_bucket{device="sda",operation="read",le="16384"} 398
ebpf_exporter_bio_size_bucket{device="sda",operation="read",le="32768"} 398
ebpf_exporter_bio_size_bucket{device="sda",operation="read",le="+Inf"} 398
ebpf_exporter_bio_size_sum{device="sda",operation="read"} 0
ebpf_exporter_bio_size_count{device="sda",operation="read"} 398
ebpf_exporter_bio_size_bucket{device="sda",operation="write",le="1"} 25
ebpf_exporter_bio_size_bucket{device="sda",operation="write",le="2"} 74
ebpf_exporter_bio_size_bucket{device="sda",operation="write",le="4"} 227
ebpf_exporter_bio_size_bucket{device="sda",operation="write",le="8"} 284
ebpf_exporter_bio_size_bucket{device="sda",operation="write",le="16"} 321
ebpf_exporter_bio_size_bucket{device="sda",operation="write",le="32"} 338
ebpf_exporter_bio_size_bucket{device="sda",operation="write",le="64"} 342
ebpf_exporter_bio_size_bucket{device="sda",operation="write",le="128"} 354
ebpf_exporter_bio_size_bucket{device="sda",operation="write",le="256"} 395
ebpf_exporter_bio_size_bucket{device="sda",operation="write",le="512"} 609
ebpf_exporter_bio_size_bucket{device="sda",operation="write",le="1024"} 1014
ebpf_exporter_bio_size_bucket{device="sda",operation="write",le="2048"} 1014
ebpf_exporter_bio_size_bucket{device="sda",operation="write",le="4096"} 1014
ebpf_exporter_bio_size_bucket{device="sda",operation="write",le="8192"} 1014
ebpf_exporter_bio_size_bucket{device="sda",operation="write",le="16384"} 1014
ebpf_exporter_bio_size_bucket{device="sda",operation="write",le="32768"} 1014
ebpf_exporter_bio_size_bucket{device="sda",operation="write",le="+Inf"} 1014
ebpf_exporter_bio_size_sum{device="sda",operation="write"} 0
ebpf_exporter_bio_size_count{device="sda",operation="write"} 1014
...
```

To nicely plot these in Grafana, you'll need v5.1:

* https://github.com/grafana/grafana/pull/11087

![Histogram](https://user-images.githubusercontent.com/89186/39159149-fbecb752-4718-11e8-8afe-0872e0996776.png)

```yaml
programs:
  - name: bio
    metrics:
      histograms:
        - name: bio_latency
          help: Block IO latency histogram with microsecond buckets
          table: io_latency
          bucket_type: exp2
          bucket_min: 0
          bucket_max: 31
          labels:
            - name: device
              decoders:
                - name: string
            - name: operation
              decoders:
                - name: static_map
                  static_map:
                    0x1: read
                    0x2: write
            - name: bucket
              decoders:
                - name: uint64
        - name: bio_size
          help: Block IO size histogram with kibibyte buckets
          table: io_size
          bucket_type: exp2
          bucket_min: 0
          bucket_max: 15
          labels:
            - name: device
              decoders:
                - name: string
            - name: operation
              decoders:
                - name: static_map
                  static_map:
                    0x1: read
                    0x2: write
            - name: bucket
              decoders:
                - name: uint64
    kprobes:
      blk_start_request: trace_req_start
      blk_mq_start_request: trace_req_start
      blk_account_io_completion: trace_req_completion
    code: |
      #include <uapi/linux/ptrace.h>
      #include <linux/blkdev.h>
      #include <linux/blk_types.h>

      typedef struct disk_key {
        char disk[DISK_NAME_LEN];
        u8 op;
        u64 slot;
      } disk_key_t;

      // Max number of disks we expect to see on the host
      const u8 max_disks = 6;

      // Hash to temporily hold the start time of each bio request, max 10k in-flight by default
      BPF_HASH(start, struct request *);

      // Histograms to record latencies, 32 buckets per disk in us (up to 2s)
      BPF_HISTOGRAM(io_latency, disk_key_t, 32 * max_disks);

      // Histograms to record sizes, 16 buckets per disk in kib (up to 32mib)
      BPF_HISTOGRAM(io_size, disk_key_t, 16 * max_disks);

      // Record start time of a request
      int trace_req_start(struct pt_regs *ctx, struct request *req)
      {
        u64 ts = bpf_ktime_get_ns();
        start.update(&req, &ts);
        return 0;
      }

      // Calculate request duration and store in appropriate histogram bucket
      int trace_req_completion(struct pt_regs *ctx, struct request *req, unsigned int bytes)
      {
        u64 *tsp, delta;

        // Fetch timestamp and calculate delta
        tsp = start.lookup(&req);
        if (tsp == 0) {
          return 0; // missed issue
        }

        delta = bpf_ktime_get_ns() - *tsp;

        // Convert to microseconds
        delta /= 1000;

        // Latency histogram key
        u64 latency_slot = bpf_log2l(delta);

        // Cap latency bucket at 31
        if (latency_slot > 31) {
          latency_slot = 31;
        }

        disk_key_t latency_key = { .slot = latency_slot };
        bpf_probe_read(&latency_key.disk, sizeof(latency_key.disk), req->rq_disk->disk_name);

        // Request size histogram key
        u64 size_slot = bpf_log2(bytes / 1024);

        // Cap latency bucket at 15
        if (size_slot > 15) {
          size_slot = 15;
        }

        disk_key_t size_key = { .slot = size_slot };
        bpf_probe_read(&size_key.disk, sizeof(size_key.disk), req->rq_disk->disk_name);

        if ((req->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE) {
          latency_key.op = 2;
          size_key.op    = 2;
        } else {
          latency_key.op = 1;
          size_key.op    = 1;
        }

        io_latency.increment(latency_key);
        io_size.increment(size_key);

        start.delete(&req);

        return 0;
      }
```

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
cannot be nested, so we need to pack keys in the kerne and unpack in user space.

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

* `bucket_type`: can be either `exp2` or `linear`
* `bucket_min`: minimum bucket key
* `bucket_max`: maximum bucket key
* `bucket_multiplier`: multiplier for linear histograms

For `exp2` histograms we expect kernel to provide a map with linear keys that
are log2 of actual values. We then go from `bucket_min` to `bucket_max` in
user space and remap keys by exponentiating them:

```
count = 0
for i = bucket_min; i < bucket_max; i++ {
  count += map.get(i, 0)
  result[exp2(i)] = count
}
```

Here `map` is the map from the kernel and `result` is what goes to prometheus.

We take cumulative `count`, because this is what prometheus expects.

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

The default value of `bucket_multiplier` is `1`.

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

Maps coming from the kernel are encoded in a special way. For example,
here's how `[sda, 1]` is encoded as a string:

```
{ "sda" 0x1 }
```

We're transforming this to `["sda", "0x1"]` and call it a set of labels.

Each label can be transformed with decoders (see below) according to metric
configuration. Generally number of labels matches number of elements
in the kernel map key.

### Decoders

Decoders take a string input of a label value and transform it to a string
output that can either be chained to another decoder or used as the final
label value.

Below are decoders we have built in.

#### `ksym`

KSym decoder takes kernel address and converts that to the function name.

In your eBPF program you can use `PT_REGS_IP(ctx)` to get the address
of the kprobe you attached to as a `u64` variable.

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
configuration key of the decoder.

An example to match `0x1` to `read` and `0x2` to `write`:

```
- name: operation
  decoder: static_map
  static_decoder_map:
    0x1: read
    0x2: write
```

#### `string`

String decoder transforms quoted strings coming from the kernel into unquoted
string usable for prometheus metrics. For example: `"sda" -> sda`.

#### `uint64`

UInt64 decoder transforms hex encoded `uint64` values from the kernel
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
krpobes:
  [ krpobename: target ... ]
# Actual eBPF program code to inject in the kernel
code: [ code ]
```

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
labels:
  [ - label ]
```

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
decoders:
  [ - decoder ]
```

#### `decoder`

See [Decoders](#decoders) section for more details.

```
name: <decoder name>
# ... decoder specific configuration
```

## License

MIT
