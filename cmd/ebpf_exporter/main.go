package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/v2/config"
	"github.com/cloudflare/ebpf_exporter/v2/exporter"
	"github.com/cloudflare/ebpf_exporter/v2/tracing"
	"github.com/coreos/go-systemd/activation"
	"github.com/mdlayher/sdnotify"
	"github.com/prometheus/client_golang/prometheus"
	version_collector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"go.opentelemetry.io/otel/sdk/trace"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

func main() {
	configDir := kingpin.Flag("config.dir", "Config dir path.").Required().ExistingDir()
	configNames := kingpin.Flag("config.names", "Comma separated names of configs to load.").Required().String()
	configCheck := kingpin.Flag("config.check", "Check whether configs attach and exit.").Bool()
	configStrict := kingpin.Flag("config.strict", "Make sure every probe registered.").Bool()
	debug := kingpin.Flag("debug", "Enable debug.").Bool()
	noLogTime := kingpin.Flag("log.no-timestamps", "Disable timestamps in log.").Bool()
	listenAddress := kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests (fd://0 for systemd activation).").Default(":9435").String()
	metricsPath := kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
	capabilities := kingpin.Flag("capabilities.keep", "Comma separated list of capabilities to keep (cap_syslog, cap_bpf, etc.), 'all' or 'none'").Default("all").String()
	btfPath := kingpin.Flag("btf.path", "Optional BTF file path.").Default("").String()
	skipCacheSize := kingpin.Flag("config.skip-cache-size", "Size of the LRU skip cache").Int()
	kingpin.Version(version.Print("ebpf_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	libbpfgoCallbacks := libbpfgo.Callbacks{Log: libbpfLogCallback}
	if !*debug {
		libbpfgoCallbacks.LogFilters = append(libbpfgoCallbacks.LogFilters, func(libLevel int, _ string) bool {
			return libLevel == libbpfgo.LibbpfDebugLevel
		})
	}

	if *noLogTime {
		log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	}

	if libbpfgo.MajorVersion() != 1 {
		log.Fatalf("Error: running with libbpf v%d.%d, v1.x is expected", libbpfgo.MajorVersion(), libbpfgo.MinorVersion())
	}

	libbpfgo.SetLoggerCbs(libbpfgoCallbacks)

	notifier, _ := sdnotify.New()

	notify := func(format string, v ...interface{}) {
		if notifier == nil {
			return
		}

		_ = notifier.Notify(sdnotify.Statusf(format, v...))
	}

	started := time.Now()

	notify("parsing config...")

	configs, err := config.ParseConfigs(*configDir, strings.Split(*configNames, ","))
	if err != nil {
		log.Fatalf("Error parsing configs: %v", err)
	}

	if os.Getenv("OTEL_SERVICE_NAME") == "" {
		os.Setenv("OTEL_SERVICE_NAME", "ebpf_exporter")
	}

	processor, err := tracing.NewProcessor()
	if err != nil {
		log.Fatalf("Error creating tracing processor: %v", err)
	}

	notify("creating exporter...")

	e, err := exporter.New(configs, *skipCacheSize, tracing.NewProvider(processor), *btfPath)
	if err != nil {
		log.Fatalf("Error creating exporter: %s", err)
	}

	notify("attaching configs...")

	err = e.Attach()
	if err != nil {
		log.Fatalf("Error attaching exporter: %s", err)
	}

	err = ensureCapabilities(*capabilities)
	if err != nil {
		log.Fatalf("Error dropping capabilities: %s", err)
	}

	readyString := fmt.Sprintf("%d programs found in the config in %dms", len(configs), time.Since(started).Milliseconds())

	log.Printf("Started with %s", readyString)

	if *configStrict {
		missed := e.MissedAttachments()
		if len(missed) > 0 {
			log.Fatalf("Missed attachments (module:prog): %v", strings.Join(missed, ", "))
		}
	}

	if *configCheck {
		log.Printf("Config check successful, exiting")
		return
	}

	err = prometheus.Register(version_collector.NewCollector("ebpf_exporter"))
	if err != nil {
		log.Fatalf("Error registering version collector: %s", err)
	}

	err = prometheus.Register(e)
	if err != nil {
		log.Fatalf("Error registering exporter: %s", err)
	}

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, err = w.Write([]byte(`<html>
			<head><title>eBPF Exporter</title></head>
			<body>
			<h1>eBPF Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
		if err != nil {
			log.Fatalf("Error sending response body: %s", err)
		}
	})

	if *debug {
		log.Printf("Debug enabled, exporting raw maps on /maps")
		http.HandleFunc("/maps", e.MapsHandler)
	}

	listener, err := listen(*listenAddress)
	if err != nil {
		log.Fatalf("Error listening on %s: %v", *listenAddress, err)
	}

	notify("ready with %s", readyString)

	if notifier != nil {
		_ = notifier.Notify(sdnotify.Ready)
	}

	go handleSignals(e, processor, notifier)

	err = http.Serve(listener, nil)
	if err != nil {
		log.Fatalf("Error serving HTTP: %v", err)
	}
}

func listen(addr string) (net.Listener, error) {
	log.Printf("Listening on %s", addr)
	if strings.HasPrefix(addr, "fd://") {
		fd, err := strconv.Atoi(strings.TrimPrefix(addr, "fd://"))
		if err != nil {
			return nil, fmt.Errorf("error extracting fd number from %q: %w", addr, err)
		}

		listeners, err := activation.Listeners()
		if err != nil {
			return nil, fmt.Errorf("error getting activation listeners: %w", err)
		}

		if len(listeners) < fd+1 {
			return nil, errors.New("no listeners passed via activation")
		}

		return listeners[fd], nil
	}

	return net.Listen("tcp", addr)
}

func ensureCapabilities(keep string) error {
	existing := cap.GetProc()
	log.Printf("Started with capabilities: %q", existing)

	if keep == "all" {
		log.Printf("Retaining all existing capabilities")
		return nil
	}

	ensure := cap.NewSet()

	values := []cap.Value{}
	if keep != "none" {
		for _, name := range strings.Split(keep, ",") {
			value, err := cap.FromName(name)
			if err != nil {
				return fmt.Errorf("error parsing capability %q: %w", name, err)
			}

			values = append(values, value)
		}
	}

	err := ensure.SetFlag(cap.Permitted, true, values...)
	if err != nil {
		return fmt.Errorf("error setting permitted capabilities: %w", err)
	}

	err = ensure.SetFlag(cap.Effective, true, values...)
	if err != nil {
		return fmt.Errorf("error setting effective capabilities: %w", err)
	}

	err = ensure.SetProc()
	if err != nil {
		return fmt.Errorf("failed to drop capabilities: %q -> %q: %w", existing, ensure, err)
	}

	log.Printf("Dropped capabilities to %q", ensure)

	return nil
}

func handleSignals(e *exporter.Exporter, processor trace.SpanProcessor, notifier *sdnotify.Notifier) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	sig := <-signals

	log.Printf("Received signal: %v", sig)

	if notifier != nil {
		_ = notifier.Notify(sdnotify.Stopping)
	}

	started := time.Now()

	e.Detach()

	log.Printf("Detached in %dms", time.Since(started).Milliseconds())

	err := processor.ForceFlush(context.Background())
	if err != nil {
		log.Fatalf("Error flushing spans: %v", err)
	}

	os.Exit(0)
}

func libbpfLogCallback(level int, msg string) {
	levelName := "unknown"
	switch level {
	case libbpfgo.LibbpfWarnLevel:
		levelName = "warn"
	case libbpfgo.LibbpfInfoLevel:
		levelName = "info"
	case libbpfgo.LibbpfDebugLevel:
		levelName = "debug"
	}

	log.Printf("libbpf [%s]: %s", levelName, msg)
}
