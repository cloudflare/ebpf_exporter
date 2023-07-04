.DEFAULT_GOAL := build

.PHONY: clean
clean:
	$(MAKE) -C probes clean

.PHONY: build
build:
	$(MAKE) -C probes build

.PHONY: run
run: build
	sudo GOMAXPROCS=1 CGO_LDFLAGS="-l bpf" go test -bench .
