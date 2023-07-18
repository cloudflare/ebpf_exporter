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

func BenchmarkGetpidWithoutAnyProbes(b *testing.B) {
	b.Run("getpid", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			os.Getpid()
		}
	})
}

func BenchmarkGetpidTracepointWithNoMap(b *testing.B) {
	benchmarkWithProbe(b, "tracepoint", "probes/tracepoint-empty.bpf.o", false)
}

func BenchmarkGetpidTracepointWithSimpleMap(b *testing.B) {
	benchmarkWithProbe(b, "tracepoint", "probes/tracepoint-simple.bpf.o", true)
}

func BenchmarkGetpidTracepointWithComplexMap(b *testing.B) {
	benchmarkWithProbe(b, "tracepoint", "probes/tracepoint-complex.bpf.o", true)
}

func BenchmarkGetpidFentryWithNoMap(b *testing.B) {
	benchmarkWithProbe(b, "fentry", "probes/fentry-empty.bpf.o", false)
}

func BenchmarkGetpidFentryWithSimpleMap(b *testing.B) {
	benchmarkWithProbe(b, "fentry", "probes/fentry-simple.bpf.o", true)
}

func BenchmarkGetpidFentryWithComplexMap(b *testing.B) {
	benchmarkWithProbe(b, "fentry", "probes/fentry-complex.bpf.o", true)
}

func BenchmarkGetpidKprobeWithNoMap(b *testing.B) {
	benchmarkWithProbe(b, "kprobe", "probes/kprobe-empty.bpf.o", false)
}

func BenchmarkGetpidKprobeWithSimpleMap(b *testing.B) {
	benchmarkWithProbe(b, "kprobe", "probes/kprobe-simple.bpf.o", true)
}

func BenchmarkGetpidKprobeWithComplexMap(b *testing.B) {
	benchmarkWithProbe(b, "kprobe", "probes/kprobe-complex.bpf.o", true)
}

func benchmarkWithProbe(b *testing.B, kind string, file string, checkMap bool) {
	byteOrder := util.GetHostByteOrder()

	m, link, err := setupGetpidProbe(kind, file)
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

	b.Run("getpid", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			os.Getpid()
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
		keys += 1
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

func setupGetpidProbe(kind string, name string) (*libbpfgo.Module, *libbpfgo.BPFLink, error) {
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
