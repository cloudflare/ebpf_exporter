.DEFAULT_GOAL := build

CC := clang

ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')

SRC = ${wildcard *.bpf.c}
OBJ = ${patsubst %.bpf.c, %.bpf.o, $(SRC)}
HDR = ${wildcard *.h}

include ../../Makefile.libbpf

$(OBJ): %.bpf.o: %.bpf.c $(HDR) ../../include/$(ARCH)/vmlinux.h $(LIBBPF_DEPS)
	$(CC) -mcpu=v3 -g -O2 -Wall -Werror -D__TARGET_ARCH_$(ARCH) -I../../include/$(ARCH) $(LIBBPF_CFLAGS) -c -target bpf $< -o $@

.PHONY: clean
clean:
	rm -f *.o

.PHONY: build
build: $(OBJ)
