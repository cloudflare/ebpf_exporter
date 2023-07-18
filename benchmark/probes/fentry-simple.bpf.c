#define BENCHMARK_SIMPLE_MAP
#include "benchmark.bpf.h"

BENCHMARK_PROBE(FENTRY_SEC, simple_probe);
