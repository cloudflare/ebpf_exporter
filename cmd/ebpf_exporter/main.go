package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/v2/config"
	"github.com/cloudflare/ebpf_exporter/v2/exporter"
	"github.com/coreos/go-systemd/activation"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"gopkg.in/alecthomas/kingpin.v2"
)

func main() {
	configDir := kingpin.Flag("config.dir", "Config dir path.").Required().ExistingDir()
	configNames := kingpin.Flag("config.names", "Comma separated names of configs to load.").Required().String()
	debug := kingpin.Flag("debug", "Enable debug.").Bool()
	noLogTime := kingpin.Flag("log.no-timestamps", "Disable timestamps in log.").Bool()
	listenAddress := kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests (fd://0 for systemd activation).").Default(":9435").String()
	metricsPath := kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
	kingpin.Version(version.Print("ebpf_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	libbpfgoCallbacks := libbpfgo.Callbacks{Log: libbpfLogCallback}
	if !*debug {
		libbpfgoCallbacks.LogFilters = append(libbpfgoCallbacks.LogFilters, func(libLevel int, msg string) bool {
			return libLevel == libbpfgo.LibbpfDebugLevel
		})
	}

	if *noLogTime {
		log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	}

	libbpfgo.SetLoggerCbs(libbpfgoCallbacks)

	started := time.Now()

	configs, err := config.ParseConfigs(*configDir, strings.Split(*configNames, ","))
	if err != nil {
		log.Fatalf("Error parsing configs: %v", err)
	}

	e, err := exporter.New(configs)
	if err != nil {
		log.Fatalf("Error creating exporter: %s", err)
	}

	err = e.Attach()
	if err != nil {
		log.Fatalf("Error attaching exporter: %s", err)
	}

	log.Printf("Started with %d programs found in the config in %dms", len(configs), time.Since(started).Milliseconds())

	err = prometheus.Register(version.NewCollector("ebpf_exporter"))
	if err != nil {
		log.Fatalf("Error registering version collector: %s", err)
	}

	err = prometheus.Register(e)
	if err != nil {
		log.Fatalf("Error registering exporter: %s", err)
	}

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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

	err = listen(*listenAddress)
	if err != nil {
		log.Fatalf("Error listening on %s: %s", *listenAddress, err)
	}
}

func listen(addr string) error {
	log.Printf("Listening on %s", addr)
	if strings.HasPrefix(addr, "fd://") {
		fd, err := strconv.Atoi(strings.TrimPrefix(addr, "fd://"))
		if err != nil {
			return fmt.Errorf("error extracting fd number from %q: %v", addr, err)
		}

		listeners, err := activation.Listeners()
		if err != nil {
			return fmt.Errorf("error getting activation listeners: %v", err)
		}

		if len(listeners) < fd+1 {
			return fmt.Errorf("no listeners passed via activation")
		}

		return http.Serve(listeners[fd], nil)
	}

	return http.ListenAndServe(addr, nil)

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
