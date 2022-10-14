FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl git ca-certificates build-essential libelf-dev gnupg2

RUN echo 'deb https://ppa.launchpadcontent.net/longsleep/golang-backports/ubuntu jammy main' > /etc/apt/sources.list.d/golang-backports.list && \
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 52b59b1571a79dbc054901c0f6bc817356a3d45e && \
    apt-get update && \
    apt-get install -y --no-install-recommends golang-1.19-go

RUN mkdir /build

RUN git clone --branch v1.0.1 --depth 1 https://github.com/libbpf/libbpf.git /build/libbpf && \
    make -C /build/libbpf/src BUILD_STATIC_ONLY=y LIBSUBDIR=lib install

COPY ./ /build/ebpf_exporter

RUN cd /build/ebpf_exporter && PATH="/usr/lib/go-1.19/bin:$PATH" CGO_LDFLAGS="-l bpf" GOFLAGS="-mod=vendor" go build -o /usr/sbin/ebpf_exporter -v -ldflags=" \
    -extldflags "-static" \
    -X github.com/prometheus/common/version.Version=$(git describe) \
    -X github.com/prometheus/common/version.Branch=$(git rev-parse --abbrev-ref HEAD) \
    -X github.com/prometheus/common/version.Revision=$(git rev-parse --short HEAD) \
    -X github.com/prometheus/common/version.BuildUser=docker@$(hostname) \
    -X github.com/prometheus/common/version.BuildDate=$(date --iso-8601=seconds) \
    " ./cmd/ebpf_exporter

RUN /usr/sbin/ebpf_exporter --version
