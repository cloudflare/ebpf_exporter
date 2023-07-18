#define BENCHMARK_NO_MAP
#include "benchmark.bpf.h"

BENCHMARK_PROBE(FENTRY_SEC, empty_probe);
