#define BENCHMARK_SIMPLE_MAP
#include "benchmark.bpf.h"

BENCHMARK_PROBE(TRACEPOINT_SEC, simple_probe);
