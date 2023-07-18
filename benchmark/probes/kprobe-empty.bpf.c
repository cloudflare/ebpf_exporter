#define BENCHMARK_NO_MAP
#include "benchmark.bpf.h"

BENCHMARK_PROBE(KPROBE_SEC, empty_probe);
