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

On idle Xeon Gold 6262 @ 1.90GHz running vanilla Linux 5.15.40 with
turbo disabled for stable measurements we see the following numbers:

```
$ make clean run
BenchmarkGetpidWithNoProbes/getpid         	 1882503	       637.9 ns/op
BenchmarkGetpidWithSimpleMap/getpid        	 1633400	       749.8 ns/op
BenchmarkGetpidWithComplexMap/getpid       	 1255801	       955.0 ns/op
```

With turbo you can see better numbers:

```
BenchmarkGetpidWithNoProbes/getpid         	 2475504	       484.4 ns/op
BenchmarkGetpidWithSimpleMap/getpid        	 2145756	       565.6 ns/op
BenchmarkGetpidWithComplexMap/getpid       	 1706983	       709.9 ns/op
```

On Ampere Altra Max numbers are better:

```
BenchmarkGetpidWithNoProbes/getpid         	 3740620	       322.9 ns/op
BenchmarkGetpidWithSimpleMap/getpid        	 2444229	       488.9 ns/op
BenchmarkGetpidWithComplexMap/getpid       	 2007832	       597.6 ns/op
```

| CPU             | Case     | ns/op | overhead ns/op | overhead percent |
|:----------------|:---------|------:|---------------:|-----------------:|
| Intel w/o turbo | no probe |   638 |              0 |               0% |
|                 | simple   |   750 |            112 |              17% |
|                 | complex  |   955 |            317 |              50% |
| Intel w/o turbo | no probe |   484 |              0 |               0% |
|                 | simple   |   567 |             83 |              17% |
|                 | complex  |   710 |            226 |              47% |
| Ampere          | no probe |   323 |              0 |               0% |
|                 | simple   |   489 |            166 |              51% |
|                 | complex  |   597 |            274 |              85% |

Double digit % slowdown for complex case may sounds like terrible,
but you have to remember that we're using a fast `getpid()` syscall.

The main number to look at above is overhead in nanoseconds, because that's
what you're going to pay no matter how fast or frequent function you're
probing is. 200-300ns overhead for the complex case of `getpid` is a lot, but for
tracing operations like disk access it's nothing compared to baseline.

Keep in mind that these numbers are for a single logical CPU core.

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
