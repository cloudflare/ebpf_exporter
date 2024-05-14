.DEFAULT_GOAL := build

BUILD_VAR_PREFIX := github.com/prometheus/common/version
BUILD_USER := $(shell id -u -n)@$(shell hostname)
BUILD_DATE := $(shell date --iso-8601=seconds)

ifeq (yes,$(shell which git > /dev/null && test -e .git && echo yes))
BUILD_VERSION := $(shell git describe --tags)
BUILD_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
BUILD_REVISION := $(shell git rev-parse --short HEAD)
else
BUILD_VERSION := unknown
BUILD_BRANCH := unknown
BUILD_REVISION := unknown
endif

GO_LDFLAGS_VARS := -X $(BUILD_VAR_PREFIX).Version=$(BUILD_VERSION) \
	-X $(BUILD_VAR_PREFIX).Branch=$(BUILD_BRANCH) \
	-X $(BUILD_VAR_PREFIX).Revision=$(BUILD_REVISION) \
	-X $(BUILD_VAR_PREFIX).BuildUser=$(BUILD_USER) \
	-X $(BUILD_VAR_PREFIX).BuildDate=$(BUILD_DATE)

CLANG_FORMAT_FILES = ${wildcard examples/*.c examples/*.h benchmark/probes/*.c benchmark/probes/*.h}

# * cachestat-pre-kernel-5.16 fails to attach in newer kernels (see code)
# * llcstat requires real hardware to attach perf events, which is not present in ci
# * unix-socket-backlog requires a newer kernel than we have in ci
# * usdt depends on python:function__entry which is missing from ubuntu 24.04
CONFIGS_TO_IGNORE_IN_CHECK := cachestat-pre-kernel-5.16 llcstat unix-socket-backlog usdt
CONFIGS_TO_CHECK := $(filter-out $(CONFIGS_TO_IGNORE_IN_CHECK), ${patsubst examples/%.yaml, %, ${wildcard examples/*.yaml}})

CGO_LDFLAGS := -l bpf

# If libelf is new and it links to zstd, then zstd needs to be manually linked in.
ifneq ($(shell ldd $(shell /sbin/ldconfig -n -p | grep libelf.so.1 | awk '{ print $$NF }') | grep zstd),)
CGO_LDFLAGS := $(CGO_LDFLAGS) -l zstd
endif

include Makefile.libbpf

GO_TEST_ARGS = -v
# On aarch64 it's unavailable: FATAL: ThreadSanitizer: unsupported VMA range
ifneq ($(shell uname -m),aarch64)
GO_TEST_ARGS += -race
endif

.PHONY: lint
lint:
	go mod verify
	CGO_LDFLAGS="$(CGO_LDFLAGS)" CGO_CFLAGS="$(CGO_CFLAGS)" golangci-lint run ./...

.PHONY: jsonschema
jsonschema:
	./scripts/jsonschema.sh

.PHONY: clang-format-check
clang-format-check:
	./scripts/clang-format-check.sh $(CLANG_FORMAT_FILES)

.PHONY: test
test: $(LIBBPF_DEPS)
	CGO_LDFLAGS="$(CGO_LDFLAGS)" CGO_CFLAGS="$(CGO_CFLAGS)" go test -ldflags='-extldflags "-static"' $(GO_TEST_ARGS) ./...

.PHONY: test-privileged
test-privileged:
	sudo go test $(GO_TEST_ARGS) ./cgroup

.PHONY: config-check
config-check:
	sudo ./ebpf_exporter --capabilities.keep=none --config.check --config.strict --config.dir=examples --config.names=$(shell echo $(CONFIGS_TO_CHECK) | tr ' ' ',')

.PHONY: build
build: build-static

.PHONY: build-static
build-static:
	$(MAKE) build-binary GO_BUILD_ARGS="-tags netgo,osusergo" GO_LDFLAGS='-extldflags "-static"'

.PHONY: build-dynamic
build-dynamic:
	$(MAKE) build-binary

.PHONY: build-binary
build-binary: $(LIBBPF_DEPS)
	CGO_LDFLAGS="$(CGO_LDFLAGS)" CGO_CFLAGS="$(CGO_CFLAGS)" go build $(GO_BUILD_ARGS) -o ebpf_exporter -v -ldflags="$(GO_LDFLAGS) $(GO_LDFLAGS_VARS)" ./cmd/ebpf_exporter

.PHONY: examples
examples:
	$(MAKE) -C examples

.PHONY: tracing-demos
tracing-demos:
	$(MAKE) -C tracing/demos

.PHONY: syscalls
syscalls:
	go run ./scripts/mksyscalls --strace.version v6.8

.PHONY: clean
clean:
	rm -rf ebpf_exporter libbpf
	$(MAKE) -C tracing/demos clean
	$(MAKE) -C examples clean
	$(MAKE) -C benchmark clean
