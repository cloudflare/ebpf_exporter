#define BENCHMARK_SIMPLE_MAP
#include "benchmark.bpf.h"

BENCHMARK_PROBE(KPROBE_SEC, simple_probe);
