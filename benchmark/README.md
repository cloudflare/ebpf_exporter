# eBPF overhead benchmark

This is a simple eBPF benchmark showing overhead of eBPF probes.

## Setup

We're using `getpid()` as a simple syscall to provide a reference. To measure
overhead of eBPF we measure performance in the following cases:

* No probes attached
* Simple kprobe incrementing hash map with pid as a key
* Complex kprobe incrementing hash map with a complex key:
  * PID
  * Random number obtained as `time_in_ns % 10000`
  * Command name up to 32 chars

You can see exact code of probes in `getpid_test.go`.

## Results

On idle Xeon E5-2630 v3 @ 2.40GHz running vanilla Linux 4.14.15
with turbo disabled for stable measurements we see the following numbers:

```
$ sudo GOMAXPROCS=1 GOPATH=$GOPATH taskset -c 30 go test -bench .
goos: linux
goarch: amd64
pkg: github.com/cloudflare/ebpf_exporter/benchmark
BenchmarkGetpid               	 5000000	       316 ns/op
BenchmarkGetpidWithSimpleMap  	 3000000	       424 ns/op
BenchmarkGetpidWithComplexMap 	 2000000	       647 ns/op
PASS
ok  	github.com/cloudflare/ebpf_exporter/benchmark	7.328s
```

| Case     | ns/op | overhead ns/op | ops/s     | overhead percent |
|:---------|------:|---------------:|----------:|-----------------:|
| no probe |   316 |              0 | 3,164,556 |               0% |
| simple   |   424 |            108 | 2,358,490 |              34% |
| complex  |   647 |            331 | 1,545,595 |             105% |

105% slowdown for complex case may sounds like a terrible performance hit,
but you have to remember that we're using a relatively fast `getpid()` syscall.

The main number to look at above is overhead in nanoseconds, because that's
what you're going to pay no matter how fast or frequent function you're
probing is. 331ns overhead for the complex case of `getpid` is a lot, but for
tracing operations like disk access it's nothing even on fastest storage.

Keep in mind that these numbers are for a single logical CPU core.

## Estimating cost of existing function calls

You can use `funclatency` from [bcc-tools](https://github.com/iovisor/bcc)
to estimate cost of function calls in the kernel.

Example for `getpid` syscall:

```
$ sudo /usr/share/bcc/tools/funclatency sys_getpid
Tracing 1 functions for "sys_getpid"... Hit Ctrl-C to end.
^C
     nsecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 52       |**                                      |
       256 -> 511        : 703      |****************************************|
       512 -> 1023       : 39       |**                                      |
      1024 -> 2047       : 48       |**                                      |
      2048 -> 4095       : 46       |**                                      |
      4096 -> 8191       : 0        |                                        |
      8192 -> 16383      : 1        |                                        |
```

These measurements already include some overhead from `funclatency` itself.

You can see frequency of calls in the output as well.

## Performance analysis with perf

See [`ebpf_exporter_ebpf_programs`](../README.md#ebpf_exporter_ebpf_programs)
for more information on runtime analysis of performance impact.
