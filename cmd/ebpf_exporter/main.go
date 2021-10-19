package main

import (
	"log"
	"net/http"

	"github.com/cloudflare/ebpf_exporter/config"
	"github.com/cloudflare/ebpf_exporter/exporter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	yaml "gopkg.in/yaml.v2"
)

func main() {
	configFile := kingpin.Flag("config.file", "Config file path").File()
	debug := kingpin.Flag("debug", "Enable debug").Bool()
	listenAddress := kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests").Default(":9435").String()
	metricsPath := kingpin.Flag("web.telemetry-path", "Path under which to expose metrics").Default("/metrics").String()
	kingpin.Version(version.Print("ebpf_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	config := config.Config{}

	err := yaml.NewDecoder(*configFile).Decode(&config)
	if err != nil {
		log.Fatalf("Error reading config file: %s", err)
	}

	e, err := exporter.New(config)
	if err != nil {
		log.Fatalf("Error creating exporter: %s", err)
	}

	err = e.Attach()
	if err != nil {
		log.Fatalf("Error attaching exporter: %s", err)
	}

	log.Printf("Starting with %d programs found in the config", len(config.Programs))

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
		log.Printf("Debug enabled, exporting raw tables on /tables")
		http.HandleFunc("/tables", e.TablesHandler)
	}

	log.Printf("Listening on %s", *listenAddress)
	err = http.ListenAndServe(*listenAddress, nil)
	if err != nil {
		log.Fatalf("Error listening on %s: %s", *listenAddress, err)
	}
}
