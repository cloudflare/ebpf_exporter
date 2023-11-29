#define BENCHMARK_COMPLEX_MAP
#include "benchmark.bpf.h"

BENCHMARK_PROBE(UPROBE_SEC, complex_probe);
