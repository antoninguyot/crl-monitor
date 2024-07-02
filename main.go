package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var expirationTime = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "crl_monitor_expire_time_seconds",
	Help: "Expiration time of CRLs in seconds since epoch",
}, []string{"crldp"})

var generationTime = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "crl_monitor_generate_time_seconds",
	Help: "Generation time of CRLs in seconds since epoch",
}, []string{"crldp"})

var k = koanf.New(".")

func main() {
	var refreshInterval time.Duration
	var configFile string
	flag.DurationVar(&refreshInterval, "refresh-interval", time.Hour, "interval at which CRLs are fetched from distribution points")
	flag.StringVar(&configFile, "config", "", "config file listing CRLs to monitor")
	flag.Parse()

	if configFile == "" {
		log.Fatalf("Please specify a config file with -config")
	}

	f := file.Provider(configFile)
	if err := k.Load(f, yaml.Parser()); err != nil {
		log.Fatalf("error loading config: %s", err)
	}

	if err := k.Load(f, yaml.Parser()); err != nil {
		log.Fatalf("error loading config: %s", err)
	}

	f.Watch(func(event interface{}, err error) {
		if err != nil {
			log.Printf("watch error: %s", err)
			return
		}

		// Throw away the old config and load a fresh copy.
		log.Println("config changed. Reloading ...")
		k = koanf.New(".")
		k.Load(f, yaml.Parser())
		updateMetrics()
	})

	go monitorCRLs(refreshInterval)

	r := prometheus.NewRegistry()
	r.MustRegister(generationTime, expirationTime)

	http.Handle("/metrics", promhttp.HandlerFor(r, promhttp.HandlerOpts{}))
	log.Fatal(http.ListenAndServe(":2112", nil))
}

func monitorCRLs(refreshInterval time.Duration) {
	for {
		err := updateMetrics()
		if err != nil {
			log.Printf("Error updating metrics: %s", err)
		}
		time.Sleep(refreshInterval)
	}
}

func updateMetrics() error {
	for _, crlDp := range k.Strings("crls") {
		crlUrl, err := url.Parse(crlDp)
		if err != nil {
			log.Fatalf("Error parsing URL: %s", err)
		}
		crl, err := fetchCrl(*crlUrl)
		if err != nil {
			log.Fatalf("Error fetching CRL: %s", err)
		}
		generationTime.WithLabelValues(crlDp).Set(float64(crl.ThisUpdate.Unix()))
		expirationTime.WithLabelValues(crlDp).Set(float64(crl.NextUpdate.Unix()))
	}

	return nil
}

func fetchCrl(url url.URL) (*x509.RevocationList, error) {
	log.Printf("Fetching CRL at %s", url.String())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching CRL at %s: %s", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body of CRL at %s: %s", url, err)
	}

	// Parse the CRL
	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, fmt.Errorf("error parsing CRL at %s: %s", url, err)
	}

	return crl, nil

}
