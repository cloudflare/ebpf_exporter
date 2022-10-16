package benchmark

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/util"
)

func BenchmarkGetpidWithNoProbes(b *testing.B) {
	b.Run("getpid", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			os.Getpid()
		}
	})

}

func BenchmarkGetpidWithSimpleMap(b *testing.B) {
	benchmarkWithProbe(b, "probes/simple.libbpfgo.o")
}

func BenchmarkGetpidWithComplexMap(b *testing.B) {
	benchmarkWithProbe(b, "probes/complex.libbpfgo.o")
}

func benchmarkWithProbe(b *testing.B, text string) {
	byteOrder := util.GetHostByteOrder()

	m, err := setupGetpidProbe(text)
	if err != nil {
		b.Fatalf("Error setting up getpid probe: %s", err)
	}

	defer m.Close()

	b.Run("getpid", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			os.Getpid()
		}
	})

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

func setupGetpidProbe(name string) (*libbpfgo.Module, error) {
	module, err := libbpfgo.NewModuleFromFile(name)
	if err != nil {
		return nil, fmt.Errorf("error creating module from file %q: %v", name, err)
	}

	err = module.BPFLoadObject()
	if err != nil {
		return nil, fmt.Errorf("error loading bpf object from file %q: %v", name, err)
	}

	prog, err := module.GetProgram("kprobe__sys_getpid")
	if err != nil {
		return nil, fmt.Errorf("error loading program from file %q: %v", name, err)
	}

	_, err = prog.AttachKprobe(getPidProbeName())
	if err != nil {
		return nil, fmt.Errorf("error attaching probe from file %q: %v", name, err)
	}

	return module, nil
}

func getPidProbeName() string {
	switch runtime.GOARCH {
	case "arm64":
		return "__arm64_sys_getpid"
	case "amd64":
		return "__x64_sys_getpid"
	default:
		panic("unknown arch to resolve sys_getpid symbol")
	}
}
