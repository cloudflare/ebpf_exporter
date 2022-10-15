CC := clang

ARCH := $(shell uname -m)

SRC = ${wildcard *.bpf.c}
OBJ = ${patsubst %.bpf.c, %.bpf.o, $(SRC)}

$(OBJ): %.bpf.o: %.bpf.c
	$(CC) -g -O2 -I../../include -c -target bpf $< -o $@

.PHONY: clean
clean:
	rm -f *.o

.PHONY: build
build: $(OBJ)
