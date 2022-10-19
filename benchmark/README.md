# eBPF overhead benchmark

This is a simple eBPF benchmark showing overhead of eBPF probes.

## Setup

We're using `getpid()` as a simple syscall to provide a reference. To measure
the overhead of eBPF probes we measure performance in the following cases:

* No probes attached
* Simple kprobe incrementing hash map with pid as a key
* Complex kprobe incrementing hash map with a complex key:
  * PID
  * Random number obtained as `time_in_ns % 1024`
  * Command name up to 32 chars

You can see exact code of probes in [`probes` directory](probes).

## Results

The results below are from MacBook Air (M1, 2020) running Linux 6.1-rc1
in QEMU with ftrace direct call patches applied to enable `fentry`:

* https://patchwork.kernel.org/project/netdevbpf/cover/20220913162732.163631-1-xukuohai@huaweicloud.com/

We see the following results:

```
BenchmarkGetpidWithoutAnyProbes/getpid         	10949119	       106.3 ns/op
BenchmarkGetpidFentryWithSimpleMap/getpid      	 8035327	       149.7 ns/op
BenchmarkGetpidFentryWithComplexMap/getpid     	 5566742	       214.9 ns/op
BenchmarkGetpidKprobeWithSimpleMap/getpid      	 4605552	       260.6 ns/op
BenchmarkGetpidKprobeWithComplexMap/getpid     	 3604656	       330.3 ns/op
```

| Case            | ns/op | overhead ns/op | overhead percent |
|:----------------|------:|---------------:|-----------------:|
| no probe        |   106 |              0 |               0% |
| fentry simple   |   150 |             44 |              42% |
| fentry complex  |   215 |            109 |             103% |
| kprobe simple   |   261 |            155 |             146% |
| kprobe complex  |   330 |            224 |             211% |

Big slowdown in terms of % for complex case may sounds like terrible,
but you have to remember that we're using a fast `getpid()` syscall.

The main number to look at above is overhead in nanoseconds, because that's
what you're going to pay no matter how fast or frequent function you're
probing is. 200-300ns overhead for the complex case of `getpid` is a lot, but
for tracing operations like disk access it's nothing compared to baseline.

Keep in mind that these numbers are for a single logical CPU core.

Your mileage may vary depending on your hardware, make sure to test
if you are hyper sensitive to any slowdowns.

## Estimating cost of existing function calls

You can use `funclatency` from [bcc-tools](https://github.com/iovisor/bcc)
to estimate cost of function calls in the kernel to get a baseline.

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
