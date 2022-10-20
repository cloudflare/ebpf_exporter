CC := clang

ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')

SRC = ${wildcard *.bpf.c}
OBJ = ${patsubst %.bpf.c, %.bpf.o, $(SRC)}

$(OBJ): %.bpf.o: %.bpf.c
	$(CC) -g -O2 -Wall -D__TARGET_ARCH_$(ARCH) -I/usr/include/$(shell uname -m)-linux-gnu -I../include/$(ARCH) -c -target bpf $< -o $@

.PHONY: clean
clean:
	rm -f *.o

.PHONY: build
build: $(OBJ)
