# Building on Ubuntu Bionic (18.04) and supporting glibc 2.27. This allows
# the following distros (and newer versions) to run the resulting binaries:
# * Ubuntu Bionic (2.27)
# * Debian Buster (2.28)
# * CentOS 8 (2.28)
FROM ubuntu:bionic as builder

RUN apt-get update && \
    apt-get -y --no-install-recommends install build-essential fakeroot pbuilder aptitude git openssh-client ca-certificates

RUN git clone --branch=v0.22.0 --depth=1 https://github.com/iovisor/bcc.git /root/bcc && \
    git -C /root/bcc submodule update --init --recursive

RUN cd /root/bcc && \
    /usr/lib/pbuilder/pbuilder-satisfydepends && \
    PARALLEL=$(nproc) ./scripts/build-deb.sh release

FROM ubuntu:bionic

RUN apt-get update && \
    apt-get install -y --no-install-recommends git build-essential libelf1 software-properties-common

RUN add-apt-repository ppa:longsleep/golang-backports && \
    apt-get install -y --no-install-recommends golang-1.17-go

ENV PATH="/usr/lib/go-1.17/bin:$PATH"

COPY --from=builder /root/bcc/libbcc_*.deb /tmp/libbcc.deb

RUN dpkg -i /tmp/libbcc.deb

COPY ./ /go/ebpf_exporter

RUN cd /go/ebpf_exporter && \
    GOPROXY="off" GOFLAGS="-mod=vendor" go install -v -ldflags=" \
    -X github.com/prometheus/common/version.Version=$(git describe) \
    -X github.com/prometheus/common/version.Branch=$(git rev-parse --abbrev-ref HEAD) \
    -X github.com/prometheus/common/version.Revision=$(git rev-parse --short HEAD) \
    -X github.com/prometheus/common/version.BuildUser=docker@$(hostname) \
    -X github.com/prometheus/common/version.BuildDate=$(date --iso-8601=seconds) \
    " ./cmd/ebpf_exporter

RUN /root/go/bin/ebpf_exporter --version
