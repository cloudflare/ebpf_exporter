#define BENCHMARK_COMPLEX_MAP
#include "benchmark.bpf.h"

BENCHMARK_PROBE(TRACEPOINT_SEC, complex_probe);
