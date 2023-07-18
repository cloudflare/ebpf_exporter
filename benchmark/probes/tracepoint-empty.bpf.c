#define BENCHMARK_NO_MAP
#include "benchmark.bpf.h"

BENCHMARK_PROBE(TRACEPOINT_SEC, empty_probe);
