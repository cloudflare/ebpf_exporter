#define BENCHMARK_COMPLEX_MAP
#include "benchmark.bpf.h"

BENCHMARK_PROBE(FENTRY_SEC, complex_probe);
