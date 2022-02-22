.PHONY: vendor
vendor:
	docker build -t ebpf-exporter-build .
	docker run --rm -v $(CURDIR):/go/ebpf_exporter --workdir /go/ebpf_exporter --entrypoint /bin/bash ebpf-exporter-build -c "CGO_CFLAGS='-I /usr/include/bpf/' CGO_LDFLAGS='-L /root/bcc/libbpf-tools/ -l bpf' go get  ./... && go mod vendor && go mod tidy"

.PHONY: test
test:
	docker run --rm -v $(CURDIR):/go/ebpf_exporter --privileged --workdir /go/ebpf_exporter --entrypoint /bin/bash ebpf-exporter-build -c "GOPROXY='' go mod verify;CGO_CFLAGS='-I /usr/include/bpf/' CGO_LDFLAGS='-L /root/bcc/libbpf-tools/ -l bpf' go test -v ./..."
