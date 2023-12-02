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
	# We require -o benchmark.test here, because otherwise go strips symbols:
	# * https://github.com/golang/go/blob/go1.21.0/src/cmd/go/internal/test/test.go#L1028
	# * https://github.com/golang/go/blob/go1.21.0/src/cmd/go/internal/test/test.go#L630-L631
	# The symbols are necessary to attach a uprobe to itself.
	sudo GOMAXPROCS=1 CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" go test -ldflags='-extldflags "-static"' -o benchmark.test -bench .
