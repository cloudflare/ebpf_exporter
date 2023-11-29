#define BENCHMARK_SIMPLE_MAP
#include "benchmark.bpf.h"

BENCHMARK_PROBE(UPROBE_SEC, simple_probe);
