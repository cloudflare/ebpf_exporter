FROM ubuntu:22.04 as builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl git ca-certificates build-essential libelf-dev gnupg2

RUN echo 'deb https://ppa.launchpadcontent.net/longsleep/golang-backports/ubuntu jammy main' > /etc/apt/sources.list.d/golang-backports.list && \
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 52b59b1571a79dbc054901c0f6bc817356a3d45e && \
    apt-get update && \
    apt-get install -y --no-install-recommends golang-1.19-go

RUN mkdir /build

RUN git clone --branch v1.0.1 --depth 1 https://github.com/libbpf/libbpf.git /build/libbpf && \
    make -C /build/libbpf/src BUILD_STATIC_ONLY=y LIBSUBDIR=lib install

RUN tar -czf /build/libbpf.tar.gz /usr/lib/libbpf.a /usr/lib/pkgconfig/libbpf.pc /usr/include/bpf

COPY ./ /build/ebpf_exporter

RUN cd /build/ebpf_exporter && \
    PATH="/usr/lib/go-1.19/bin:$PATH" make build && \
    /build/ebpf_exporter/ebpf_exporter --version

FROM scratch as ebpf_exporter

COPY --from=builder /build/ebpf_exporter/ebpf_exporter /ebpf_exporter

ENTRYPOINT ["/ebpf_exporter"]
