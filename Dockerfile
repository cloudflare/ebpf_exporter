# libbpf
FROM debian:bookworm as libbpf_builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends git ca-certificates gcc make libelf-dev

RUN mkdir /build && \
    git clone --branch v1.2.0 --depth 1 https://github.com/libbpf/libbpf.git /build/libbpf && \
    make -j $(nproc) -C /build/libbpf/src BUILD_STATIC_ONLY=y LIBSUBDIR=lib install install_uapi_headers && \
    tar -czf /build/libbpf.tar.gz \
        /usr/lib/libbpf.a \
        /usr/lib/pkgconfig/libbpf.pc \
        /usr/include/bpf \
        /usr/include/linux/bpf.h \
        /usr/include/linux/bpf_common.h \
        /usr/include/linux/btf.h


# ebpf_exporter binary
FROM golang:1.21-bookworm as ebpf_exporter_builder

RUN apt-get update && \
    apt-get install -y libelf-dev

COPY --from=libbpf_builder /build/libbpf.tar.gz /build/libbpf.tar.gz

RUN tar -C / -xvvf /build/libbpf.tar.gz

COPY ./ /build/ebpf_exporter

RUN make -j $(nproc) -C /build/ebpf_exporter build && \
    /build/ebpf_exporter/ebpf_exporter --version


# examples
FROM debian:bookworm as examples_builder

RUN apt-get update && \
    apt-get install -y clang make

COPY --from=libbpf_builder /build/libbpf.tar.gz /build/libbpf.tar.gz

RUN tar -C / -xvvf /build/libbpf.tar.gz

COPY ./ /build/ebpf_exporter

RUN make -j $(nproc) -C /build/ebpf_exporter/examples


# ebpf_exporter release image
FROM gcr.io/distroless/static-debian11 as ebpf_exporter

COPY --from=ebpf_exporter_builder /build/ebpf_exporter/ebpf_exporter /ebpf_exporter

ENTRYPOINT ["/ebpf_exporter"]


# ebpf_exporter release image with examples bundled
FROM gcr.io/distroless/static-debian11 as ebpf_exporter_with_examples

COPY --from=ebpf_exporter_builder /build/ebpf_exporter/ebpf_exporter /ebpf_exporter
COPY --from=examples_builder /build/ebpf_exporter/examples /examples

ENTRYPOINT ["/ebpf_exporter"]
