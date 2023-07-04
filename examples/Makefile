.DEFAULT_GOAL := build

CC := clang

ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')

SRC = ${wildcard *.bpf.c}
OBJ = ${patsubst %.bpf.c, %.bpf.o, $(SRC)}

# From https://github.com/libbpf/libbpf-bootstrap/blob/a7c0f7e4a28/examples/c/Makefile#L34-L43
# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CC) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

$(OBJ): %.bpf.o: %.bpf.c ../include/$(ARCH)/vmlinux.h
	$(CC) -mcpu=v3 -g -O2 -Wall -Werror -D__TARGET_ARCH_$(ARCH) $(CFLAGS) $(CLANG_BPF_SYS_INCLUDES) -I../include/$(ARCH) -c -target bpf $< -o $@

.PHONY: clean
clean:
	rm -f *.o

.PHONY: build
build: $(OBJ)
