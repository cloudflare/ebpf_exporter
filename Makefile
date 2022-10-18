export CGO_LDFLAGS := -l bpf
export GOFLAGS := -mod=vendor

.PHONY: lint
lint:
	go mod verify
	golangci-lint run ./...

.PHONY: test
test:
	go test -v ./...

.PHONY: build
build:
	go build -o ebpf_exporter -v -ldflags=" \
		-extldflags "-static" \
		-X github.com/prometheus/common/version.Version=$(shell git describe) \
		-X github.com/prometheus/common/version.Branch=$(shell git rev-parse --abbrev-ref HEAD) \
		-X github.com/prometheus/common/version.Revision=$(shell git rev-parse --short HEAD) \
		-X github.com/prometheus/common/version.BuildUser=docker@$(shell hostname) \
		-X github.com/prometheus/common/version.BuildDate=$(shell date --iso-8601=seconds) \
		" ./cmd/ebpf_exporter
