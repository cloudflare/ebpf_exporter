# eBPF overhead benchmark

This is a simple eBPF benchmark showing overhead of eBPF probes.

## Setup

We're using `getpid()` as a simple syscall to provide a reference. To measure
the overhead of eBPF probes we measure performance in the following cases:

* No probes attached
* Empty probe doing nothing at all
* Simple probe incrementing hash map with pid as a key
* Complex probe incrementing hash map with a complex key:
  * PID
  * Random number obtained as `time_in_ns % 1024`
  * Command name up to 32 chars

You can see exact code of probes in [`probes` directory](probes).

## Results

The results below are from MacBook Air (M1, 2020) running Linux 6.5-rc1
in QEMU. We see the following results:

```
BenchmarkGetpidWithoutAnyProbes/getpid             9954225       117.3 ns/op
BenchmarkGetpidTracepointWithNoMap/getpid          9098228       132.2 ns/op
BenchmarkGetpidTracepointWithSimpleMap/getpid      7995439       152.2 ns/op
BenchmarkGetpidTracepointWithComplexMap/getpid     5655841       212.8 ns/op
BenchmarkGetpidFentryWithNoMap/getpid              8481037       141.0 ns/op
BenchmarkGetpidFentryWithSimpleMap/getpid          7582813       159.1 ns/op
BenchmarkGetpidFentryWithComplexMap/getpid         4579310       220.7 ns/op
BenchmarkGetpidKprobeWithNoMap/getpid              4725835       253.8 ns/op
BenchmarkGetpidKprobeWithSimpleMap/getpid          4306387       277.1 ns/op
BenchmarkGetpidKprobeWithComplexMap/getpid         3460576       346.3 ns/op
```

Empty probe attached:

| Case               | ns/op | Overhead ns/op | Overhead percent |
|:-------------------|------:|---------------:|-----------------:|
| no probe attached  |   117 |              0 |               0% |
| tracepoint empty   |   132 |             15 |              13% |
| fentry empty       |   141 |             24 |              21% |
| kprobe empty       |   254 |            137 |             117% |

Probe with a simple map increment attached:

| Case               | ns/op | Overhead ns/op | Overhead percent |
|:-------------------|------:|---------------:|-----------------:|
| no probe attached  |   117 |              0 |               0% |
| tracepoint simple  |   152 |             35 |              30% |
| fentry simple      |   159 |             42 |              36% |
| kprobe simple      |   277 |            160 |             136% |

Probe with a complex map increment attached:

| Case               | ns/op | Overhead ns/op | Overhead percent |
|:-------------------|------:|---------------:|-----------------:|
| no probe attached  |   117 |              0 |               0% |
| tracepoint complex |   213 |             96 |              82% |
| fentry complex     |   220 |            103 |              88% |
| kprobe complex     |   346 |            229 |             196% |

Big slowdown in terms of % for complex case may sounds like terrible,
but you have to remember that we're using a fast `getpid()` syscall.

The main number to look at above is overhead in nanoseconds, because that's
what you're going to pay no matter how fast or frequent function you're
probing is. 200-300ns overhead for the complex case of `getpid` is a lot, but
for tracing operations like disk access it's nothing compared to baseline.

Notice how tracepoints are faster than fentry and fentry is faster than kprobe.

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

## Uprobes

A similar test can be run for uprobes (Linux v6.7-rc3 on the same hardware):

```
BenchmarkUprobeTargetWithoutAnyProbes/go            1000000000           0.32 ns/op
BenchmarkUprobeTargetWithoutAnyProbes/cgo             44980404          26.65 ns/op
BenchmarkUprobeWithNoMap/cgo                            696796        1695.00 ns/op
BenchmarkUprobeWithSimpleMap/cgo                        681529        1717.00 ns/op
BenchmarkUprobeWithComplexMap/cgo                       676365        1833.00 ns/op
```

Here overhead is a lot bigger, ~1670ns per call. There's some overhead in calling
from Go into C as well and the probes attach to a C function in the benchmark.

## Performance analysis with perf

See [`ebpf_exporter_ebpf_programs`](../README.md#ebpf_exporter_ebpf_programs)
for more information on runtime analysis of performance impact.
