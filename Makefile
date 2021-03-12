.PHONY: vendor
vendor:
	docker build -t ebpf-exporter-build .
	docker run --rm -v $(CURDIR):/go/ebpf_exporter --workdir /go/ebpf_exporter --entrypoint /bin/bash ebpf-exporter-build -c "go get -u ./... && go mod vendor && go mod tidy"

.PHONY: test
test:
	GOPROXY="" go mod verify
	go test -v ./...
