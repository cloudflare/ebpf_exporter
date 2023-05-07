FROM golang:1.20-bullseye as builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends libelf-dev

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

COPY ./ /build/ebpf_exporter

RUN cd /build/ebpf_exporter && \
    make build && \
    /build/ebpf_exporter/ebpf_exporter --version

FROM gcr.io/distroless/static-debian11 as ebpf_exporter

COPY --from=builder /build/ebpf_exporter/ebpf_exporter /ebpf_exporter

ENTRYPOINT ["/ebpf_exporter"]
