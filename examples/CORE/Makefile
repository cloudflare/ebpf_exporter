# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bin/bpftool
LIBBPF_OBJ := /root/bcc/libbpf-tools/libbpf.a
CFLAGS := -g -O2 -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
INCLUDES := -I"/root/bcc/libbpf-tools/.output" -I "/root/bcc/libbpf-tools/$(ARCH)" -I"/usr/include/bpf"
OUTPUT := config

SRC = ${wildcard *.bpf.c}
OBJ = ${patsubst %.bpf.c, %.bpf.o, $(SRC)}

$(OBJ): %.bpf.o: %.bpf.c
	$(CLANG) -g -O2 $(INCLUDES) -c   -target bpf -D__TARGET_ARCH_$(ARCH) $< -o $@

.PHONY: all

all: clean $(OBJ)
	mkdir -p $(OUTPUT)
	cp *.bpf.o $(OUTPUT)
	cp config.yaml $(OUTPUT)

.PHONY: clean
clean:
	rm -f *.o
	rm -rf $(OUTPUT)
