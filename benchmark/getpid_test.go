package benchmark

import (
	"fmt"
	"os"
	"testing"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/v2/util"
)

func init() {
	libbpfgoCallbacks := libbpfgo.Callbacks{}
	libbpfgoCallbacks.LogFilters = append(libbpfgoCallbacks.LogFilters, func(libLevel int, msg string) bool {
		return libLevel == libbpfgo.LibbpfDebugLevel
	})

	libbpfgo.SetLoggerCbs(libbpfgoCallbacks)
}

func getpid() {
	os.Getpid()
}

func BenchmarkGetpidWithoutAnyProbes(b *testing.B) {
	b.Run("getpid", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			getpid()
		}
	})
}

func BenchmarkGetpidTracepointWithNoMap(b *testing.B) {
	benchmarkWithProbe(b, "probes/tracepoint-empty.bpf.o", "getpid", getpid, false)
}

func BenchmarkGetpidTracepointWithSimpleMap(b *testing.B) {
	benchmarkWithProbe(b, "probes/tracepoint-simple.bpf.o", "getpid", getpid, true)
}

func BenchmarkGetpidTracepointWithComplexMap(b *testing.B) {
	benchmarkWithProbe(b, "probes/tracepoint-complex.bpf.o", "getpid", getpid, true)
}

func BenchmarkGetpidFentryWithNoMap(b *testing.B) {
	benchmarkWithProbe(b, "probes/fentry-empty.bpf.o", "getpid", getpid, false)
}

func BenchmarkGetpidFentryWithSimpleMap(b *testing.B) {
	benchmarkWithProbe(b, "probes/fentry-simple.bpf.o", "getpid", getpid, true)
}

func BenchmarkGetpidFentryWithComplexMap(b *testing.B) {
	benchmarkWithProbe(b, "probes/fentry-complex.bpf.o", "getpid", getpid, true)
}

func BenchmarkGetpidKprobeWithNoMap(b *testing.B) {
	benchmarkWithProbe(b, "probes/kprobe-empty.bpf.o", "getpid", getpid, false)
}

func BenchmarkGetpidKprobeWithSimpleMap(b *testing.B) {
	benchmarkWithProbe(b, "probes/kprobe-simple.bpf.o", "getpid", getpid, true)
}

func BenchmarkGetpidKprobeWithComplexMap(b *testing.B) {
	benchmarkWithProbe(b, "probes/kprobe-complex.bpf.o", "getpid", getpid, true)
}

func BenchmarkUprobeTargetWithoutAnyProbes(b *testing.B) {
	b.Run("go", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			uprobeGo()
		}
	})

	b.Run("cgo", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			uprobeCgo()
		}
	})
}

func BenchmarkUprobeWithNoMap(b *testing.B) {
	benchmarkWithProbe(b, "probes/uprobe-empty.bpf.o", "cgo", uprobeCgo, false)
}

func BenchmarkUprobeWithSimpleMap(b *testing.B) {
	benchmarkWithProbe(b, "probes/uprobe-simple.bpf.o", "cgo", uprobeCgo, true)
}

func BenchmarkUprobeWithComplexMap(b *testing.B) {
	benchmarkWithProbe(b, "probes/uprobe-complex.bpf.o", "cgo", uprobeCgo, true)
}

func benchmarkWithProbe(b *testing.B, file string, target string, fn func(), checkMap bool) {
	byteOrder := util.GetHostByteOrder()

	m, link, err := setupGetpidProbe(file)
	if err != nil {
		b.Fatalf("Error setting up getpid probe: %v", err)
	}

	defer func() {
		err := link.Destroy()
		if err != nil {
			b.Fatalf("Error destroying link: %v", err)
		}
	}()

	defer m.Close()

	b.Run(target, func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			fn()
		}
	})

	if !checkMap {
		return
	}

	counts, err := m.GetMap("counts")
	if err != nil {
		b.Fatalf("Error getting map from bpf: %v", err)
	}

	keys := 0
	value := uint64(0)

	iter := counts.Iterator()
	for iter.Next() {
		keys++
		valueBytes, err := counts.GetValue(unsafe.Pointer(&iter.Key()[0]))
		if err != nil {
			b.Fatalf("Error reading key from bpf map: %v", err)
		}

		value += byteOrder.Uint64(valueBytes)
	}

	if keys == 0 {
		b.Fatal("No elements found in map")
	}

	if value < 1000 {
		b.Fatalf("Cumulative count value is too low: %d", value)
	}

	b.Logf("keys = %d, value = %d", keys, value)
}

func setupGetpidProbe(name string) (*libbpfgo.Module, *libbpfgo.BPFLink, error) {
	module, err := libbpfgo.NewModuleFromFile(name)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating module from file %q: %v", name, err)
	}

	err = module.BPFLoadObject()
	if err != nil {
		return nil, nil, fmt.Errorf("error loading bpf object from file %q: %v", name, err)
	}

	prog, err := module.GetProgram("probe")
	if err != nil {
		return nil, nil, fmt.Errorf("error loading program from file %q: %v", name, err)
	}

	link, err := prog.AttachGeneric()
	if err != nil {
		return nil, nil, fmt.Errorf("error attaching probe from file %q: %v", name, err)
	}

	return module, link, nil
}
