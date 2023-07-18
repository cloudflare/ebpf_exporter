.DEFAULT_GOAL := build

CC := clang

ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')

SRC = ${wildcard *.bpf.c}
OBJ = ${patsubst %.bpf.c, %.bpf.o, $(SRC)}

$(OBJ): %.bpf.o: %.bpf.c benchmark.bpf.h ../../include/$(ARCH)/vmlinux.h
	$(CC) -mcpu=v3 -g -O2 -Wall -Werror -D__TARGET_ARCH_$(ARCH) -I../../include/$(ARCH) -c -target bpf $< -o $@

.PHONY: clean
clean:
	rm -f *.o

.PHONY: build
build: $(OBJ)
