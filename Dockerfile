FROM golang:1.14.12-stretch

# Doing mostly what CI is doing here
RUN apt-get update && \
    apt-get install -y apt-transport-https && \
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 648A4A16A23015EEF4A66B8E4052245BD4284CDD && \
    echo "deb https://repo.iovisor.org/apt/xenial xenial main" > /etc/apt/sources.list.d/iovisor.list && \
    apt-get update && \
    apt-get install -y linux-headers-amd64 && \
    curl -sL https://github.com/cloudflare/ebpf_exporter/files/3890546/libbcc_0.11.0-2_amd64.deb.gz | gunzip > /tmp/libbcc.deb && \
    dpkg -i /tmp/libbcc.deb

COPY ./ /go/ebpf_exporter

RUN cd /go/ebpf_exporter && GOPATH="" GOPROXY="off" GOFLAGS="-mod=vendor" go install -v ./...
