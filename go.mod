module github.com/cloudflare/ebpf_exporter

require (
	github.com/alecthomas/units v0.0.0-20190924025748-f65c72e2690d // indirect
	github.com/google/go-cmp v0.3.1 // indirect
	github.com/iovisor/gobpf v0.0.0-20191212083149-cf081d8fe357
	github.com/kr/pretty v0.1.0 // indirect
	github.com/prometheus/client_golang v1.2.1
	github.com/prometheus/common v0.7.0
	golang.org/x/sys v0.0.0-20191024073052-e66fe6eb8e0c
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/yaml.v2 v2.2.4
)

// TODO: remove after https://github.com/iovisor/gobpf/pull/219 is merged
replace github.com/iovisor/gobpf => github.com/bobrik/gobpf v0.0.0-20191216233538-2cb7f18398d8

go 1.13
