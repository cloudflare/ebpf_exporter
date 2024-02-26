.DEFAULT_GOAL := build

DEMOS = $(wildcard ./*/)
BINARIES = ${patsubst %/, %/demo, $(DEMOS)}

%/demo: setup.go %/*.go
	go build -v -o $*/demo ./$*

.PHONY: build
build: $(BINARIES)

.PHONY: clean
clean:
	rm -f */demo
