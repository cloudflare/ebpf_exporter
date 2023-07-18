#define BENCHMARK_COMPLEX_MAP
#include "benchmark.bpf.h"

BENCHMARK_PROBE(KPROBE_SEC, complex_probe);
