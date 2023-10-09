# libbpf
FROM debian:bookworm as libbpf_builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends git ca-certificates gcc make pkg-config libelf-dev

COPY ./ /build/ebpf_exporter

RUN make -j $(nproc) -C /build/ebpf_exporter libbpf.a && \
    tar -C /build/ebpf_exporter/libbpf/dest -czf /build/libbpf.tar.gz .

# ebpf_exporter binary
FROM golang:1.21-bookworm as ebpf_exporter_builder

RUN apt-get update && \
    apt-get install -y libelf-dev pci.ids

COPY --from=libbpf_builder /build/ebpf_exporter/libbpf /build/ebpf_exporter/libbpf

COPY ./ /build/ebpf_exporter

RUN make -j $(nproc) -C /build/ebpf_exporter build && \
    /build/ebpf_exporter/ebpf_exporter --version


# examples
FROM debian:bookworm as examples_builder

RUN apt-get update && \
    apt-get install -y clang make

COPY --from=libbpf_builder /build/ebpf_exporter/libbpf /build/ebpf_exporter/libbpf

COPY ./ /build/ebpf_exporter

RUN make -j $(nproc) -C /build/ebpf_exporter/examples


# ebpf_exporter release image
FROM gcr.io/distroless/static-debian11 as ebpf_exporter

COPY --from=ebpf_exporter_builder /build/ebpf_exporter/ebpf_exporter /ebpf_exporter
COPY --from=ebpf_exporter_builder /usr/share/misc/pci.ids /usr/share/misc/pci.ids

ENTRYPOINT ["/ebpf_exporter"]


# ebpf_exporter release image with examples bundled
FROM gcr.io/distroless/static-debian11 as ebpf_exporter_with_examples

COPY --from=ebpf_exporter_builder /build/ebpf_exporter/ebpf_exporter /ebpf_exporter
COPY --from=ebpf_exporter_builder /usr/share/misc/pci.ids /usr/share/misc/pci.ids
COPY --from=examples_builder /build/ebpf_exporter/examples /examples

ENTRYPOINT ["/ebpf_exporter"]
