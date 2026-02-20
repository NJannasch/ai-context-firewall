package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	proxyAddr := flag.String("proxy", ":11434", "Proxy listen address")
	webAddr := flag.String("web", ":8080", "Web UI listen address")
	configPath := flag.String("config", "/etc/firewall/config.json", "Config file path")
	flag.Parse()

	// Allow environment variables to override config values
	store, err := NewStore(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	cfg := store.GetConfig()
	changed := false
	if v := os.Getenv("BACKEND_URL"); v != "" {
		cfg.BackendURL = v
		changed = true
	}
	if v := os.Getenv("INSPECTOR_URL"); v != "" {
		cfg.InspectorURL = v
		changed = true
	}
	if v := os.Getenv("INSPECTOR_MODEL"); v != "" {
		cfg.InspectorModel = v
		changed = true
	}
	if changed {
		store.SetConfig(cfg)
	}

	inspector := NewInspector(store)
	proxy := NewProxy(store, inspector)
	webServer, err := NewWebServer(store)
	if err != nil {
		log.Fatalf("failed to init web server: %v", err)
	}

	cfg = store.GetConfig()
	fmt.Println("AI Context Firewall")
	fmt.Printf("  Proxy:     %s\n", *proxyAddr)
	fmt.Printf("  Web UI:    %s\n", *webAddr)
	fmt.Printf("  Backend:   %s\n", cfg.BackendURL)
	fmt.Printf("  Inspector: %s (model: %s)\n", cfg.InspectorURL, cfg.InspectorModel)
	fmt.Printf("  Threshold: %d\n", cfg.Threshold)
	fmt.Printf("  Prompt:    %s\n", cfg.ActivePrompt)
	fmt.Println()

	errCh := make(chan error, 2)

	go func() {
		log.Printf("Proxy listening on %s", *proxyAddr)
		errCh <- http.ListenAndServe(*proxyAddr, proxy)
	}()

	go func() {
		log.Printf("Web UI listening on %s", *webAddr)
		errCh <- http.ListenAndServe(*webAddr, webServer)
	}()

	log.Fatal(<-errCh)
}
