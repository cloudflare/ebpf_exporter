#define BENCHMARK_NO_MAP
#include "benchmark.bpf.h"

BENCHMARK_PROBE(UPROBE_SEC, empty_probe);
