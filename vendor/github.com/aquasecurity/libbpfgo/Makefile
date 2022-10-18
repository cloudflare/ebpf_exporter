
.ONESHELL:
SHELL = /bin/bash

BASEDIR = $(abspath ./)

OUTPUT = ./output
SELFTEST = ./selftest
HELPERS = ./helpers

CC = gcc
CLANG = clang
GO = go
VAGRANT = vagrant
CLANG_FMT = clang-format

HOSTOS = $(shell uname)
ARCH ?= $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')

BTFFILE = /sys/kernel/btf/vmlinux
BPFTOOL = $(shell which bpftool || /bin/false)
GIT = $(shell which git || /bin/false)
VMLINUXH = $(OUTPUT)/vmlinux.h

# libbpf

LIBBPF_SRC = $(abspath ./libbpf/src)
LIBBPF_OBJ = $(abspath ./$(OUTPUT)/libbpf.a)
LIBBPF_OBJDIR = $(abspath ./$(OUTPUT)/libbpf)
LIBBPF_DESTDIR = $(abspath ./$(OUTPUT))

CFLAGS = -g -O2 -Wall -fpie
LDFLAGS =

# golang

CGO_CFLAGS_STATIC = "-I$(abspath $(OUTPUT))"
CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_OBJ)"
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'

CGO_CFLAGS_DYN = "-I. -I/usr/include/"
CGO_LDFLAGS_DYN = "-lelf -lz -lbpf"

# default == shared lib from OS package

all: libbpfgo-dynamic
test: libbpfgo-dynamic-test

# libbpfgo test object

libbpfgo-test-bpf-static: libbpfgo-static	# needed for serialization
	$(MAKE) -C $(SELFTEST)/build

libbpfgo-test-bpf-dynamic: libbpfgo-dynamic	# needed for serialization
	$(MAKE) -C $(SELFTEST)/build

libbpfgo-test-bpf-clean:
	$(MAKE) -C $(SELFTEST)/build clean

# libbpf: shared

libbpfgo-dynamic: $(OUTPUT)/libbpf
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_DYN) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_DYN) \
		$(GO) build .

libbpfgo-dynamic-test: libbpfgo-test-bpf-dynamic
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_DYN) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_DYN) \
		sudo -E $(GO) test .

# libbpf: static

libbpfgo-static: $(VMLINUXH) | $(LIBBPF_OBJ)
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
		GOOS=linux GOARCH=$(ARCH) \
		$(GO) build \
		-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
		.

libbpfgo-static-test: libbpfgo-test-bpf-static
	sudo env PATH=$(PATH) \
		CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
		GOOS=linux GOARCH=$(ARCH) \
		$(GO) test \
		-v -tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
		.

# vmlinux header file

.PHONY: vmlinuxh
vmlinuxh: $(VMLINUXH)

$(VMLINUXH): $(OUTPUT)
	@if [ ! -f $(BTFFILE) ]; then \
		echo "ERROR: kernel does not seem to support BTF"; \
		exit 1; \
	fi
	@if [ ! $(BPFTOOL) ]; then \
		echo "ERROR: could not find bpftool"; \
		exit 1; \
	fi;

	@echo "INFO: generating $(VMLINUXH) from $(BTFFILE)"; \
	if ! $(BPFTOOL) btf dump file $(BTFFILE) format c > $(VMLINUXH); then \
		echo "ERROR: could not create $(VMLINUXH)"; \
		rm -f "$(VMLINUXH)"; \
		exit 1; \
	fi;

# static libbpf generation for the git submodule

.PHONY: libbpf-static
libbpf-static: $(LIBBPF_OBJ)

$(LIBBPF_OBJ): $(LIBBPF_SRC) $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)/libbpf
	CC="$(CC)" CFLAGS="$(CFLAGS)" LD_FLAGS="$(LDFLAGS)" \
	   $(MAKE) -C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_OBJDIR) \
		DESTDIR=$(LIBBPF_DESTDIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

$(LIBBPF_SRC):
ifeq ($(wildcard $@), )
	echo "INFO: updating submodule 'libbpf'"
	$(GIT) submodule update --init --recursive
endif

# selftests

SELFTESTS = $(shell find $(SELFTEST) -mindepth 1 -maxdepth 1 -type d ! -name 'common' ! -name 'build')

define FOREACH
	SELFTESTERR=0; \
	for DIR in $(SELFTESTS); do \
	      echo "INFO: entering $$DIR..."; \
		$(MAKE) -j1 -C $$DIR $(1) || SELFTESTERR=1; \
	done; \
	if [ $$SELFTESTERR -eq 1 ]; then \
		exit 1; \
	fi
endef

.PHONY: selftest
.PHONY: selftest-static
.PHONY: selftest-dynamic
.PHONY: selftest-run
.PHONY: selftest-static-run
.PHONY: selftest-dynamic-run
.PHONY: selftest-clean

selftest: selftest-static

selftest-static:
	$(call FOREACH, main-static)
selftest-dynamic:
	$(call FOREACH, main-dynamic)

selftest-run: selftest-static-run

selftest-static-run:
	$(call FOREACH, run-static)
selftest-dynamic-run:
	$(call FOREACH, run-dynamic)

selftest-clean:
	$(call FOREACH, clean)

# helpers test

.PHONY: helpers-test-run
.PHONY: helpers-test-static-run
.PHONY: helpers-test-dynamic-run

helpers-test-run: helpers-test-static-run

helpers-test-static-run: libbpfgo-static
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
		sudo -E $(GO) test -v $(HELPERS)/...

helpers-test-dynamic-run: libbpfgo-dynamic
	sudo $(GO) test -v $(HELPERS)/...

# vagrant

VAGRANT_DIR = $(abspath ./builder)

.PHONY: vagrant-up
.PHONY: vagrant-destroy
.PHONY: vagrant-halt
.PHONY: vagrant-ssh

vagrant-up: .vagrant-up
vagrant-destroy: .vagrant-destroy
vagrant-halt: .vagrant-halt
vagrant-ssh: .vagrant-ssh

.vagrant-%:
	VAGRANT_VAGRANTFILE=$(VAGRANT_DIR)/Vagrantfile-ubuntu \
		ARCH=$(ARCH) \
		HOSTOS=$(HOSTOS) \
		$(VAGRANT) $*

# fmt-check

fmt-check:
	@errors=0
	echo "Checking C and eBPF files and headers formatting..."
	$(CLANG_FMT) --dry-run -i ./libbpfgo.h > /tmp/check-c-fmt 2>&1
	clangfmtamount=$$(cat /tmp/check-c-fmt | wc -l)
	if [[ $$clangfmtamount -ne 0 ]]; then
		head -n30 /tmp/check-c-fmt
		errors=1
	fi
	rm -f /tmp/check-c-fmt
#
	if [[ $$errors -ne 0 ]]; then
		echo
		echo "Please fix formatting errors above!"
		echo "Use: $(MAKE) fmt-fix target".
		echo
		exit 1
	fi


# fmt-fix

fmt-fix:
	@echo "Fixing C and eBPF files and headers formatting..."
	$(CLANG_FMT) -i --verbose ./libbpfgo.h

# output

$(OUTPUT):
	mkdir -p $(OUTPUT)

$(OUTPUT)/libbpf:
	mkdir -p $(OUTPUT)/libbpf

# cleanup

clean: selftest-clean libbpfgo-test-bpf-clean
	rm -rf $(OUTPUT)
