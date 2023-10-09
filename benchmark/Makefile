.DEFAULT_GOAL := build

export CGO_LDFLAGS := -l bpf

include ../Makefile.libbpf

.PHONY: clean
clean:
	$(MAKE) -C probes clean

.PHONY: build
build:
	$(MAKE) -C probes build

.PHONY: run
run: build $(LIBBPF_DEPS)
	sudo GOMAXPROCS=1 CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" go test -ldflags='-extldflags "-static"' -bench .
