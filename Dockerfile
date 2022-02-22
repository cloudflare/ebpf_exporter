# Building on Ubuntu Bionic (18.04) and supporting glibc 2.27. This allows
# the following distros (and newer versions) to run the resulting binaries:
# * Ubuntu Bionic (2.27)
# * Debian Buster (2.28)
# * CentOS 8 (2.28)
FROM ubuntu:bionic

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential git gpg-agent  pkg-config fakeroot pbuilder aptitude git  \
    openssh-client ca-certificates wget libelf-dev libz-dev software-properties-common clang

RUN wget --no-check-certificate -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
   add-apt-repository 'deb  http://apt.llvm.org/bionic/   llvm-toolchain-bionic-10  main' && \
   apt-get install -y clang-10 && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-10 100 && \
   update-alternatives --install /usr/bin/clang clang /usr/bin/clang-10 100

RUN add-apt-repository ppa:ubuntu-toolchain-r/test && apt-get install -y gcc-9 g++-9 && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 60 --slave /usr/bin/g++ g++ /usr/bin/g++-9


RUN add-apt-repository ppa:longsleep/golang-backports && \
    apt-get install -y --no-install-recommends golang-1.17-go

ENV PATH="/usr/lib/go-1.17/bin:$PATH"

RUN git clone --branch=v0.22.0 --depth=1 https://github.com/iovisor/bcc.git /root/bcc && \
    git -C /root/bcc submodule update --init --recursive

RUN cd /root && git clone https://github.com/libbpf/libbpf.git && \
    cd /root/libbpf && git checkout 030ff87857090ae5c9d74859042d05bfb3b613a2  && cd src && mkdir build root && OBJDIR=build DESTDIR=root make install

COPY ./ /go/ebpf_exporter
RUN cd  /root/libbpf/src && make install
RUN cd /go/ebpf_exporter && CGO_CFLAGS="-I /usr/include/bpf/ " CGO_LDFLAGS="-L /root/bcc/libbpf-tools/ -l bpf" GOPATH="" GOPROXY="off" GOFLAGS="-mod=vendor" go install -v -ldflags=" \
    -extldflags "-static" \
    -X github.com/prometheus/common/version.Version=$(git describe) \
    -X github.com/prometheus/common/version.Branch=$(git rev-parse --abbrev-ref HEAD) \
    -X github.com/prometheus/common/version.Revision=$(git rev-parse --short HEAD) \
    -X github.com/prometheus/common/version.BuildUser=docker@$(hostname) \
    -X github.com/prometheus/common/version.BuildDate=$(date --iso-8601=seconds) \
    " ./cmd/ebpf_exporter
RUN cd /go/ebpf_exporter/examples/CORE && make all
RUN /root/go/bin/ebpf_exporter --version
