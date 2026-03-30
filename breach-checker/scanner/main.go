package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	domain := flag.String("domain", "", "Domínio (ex: empresa.com)")
	concurrency := flag.Int("concurrency", 20, "Pedidos HTTP simultâneos")
	timeout := flag.Duration("timeout", 10*time.Second, "Timeout/pedido")
	apiKey := flag.String("api-key", os.Getenv("HIBP_API_KEY"), "Chave HIBP")
	flag.Parse()

	if *domain == "" {
		fmt.Fprintln(os.Stderr, "erro: --domain obrigatório")
		os.Exit(1)
	}

	if *apiKey == "" {
		fmt.Fprintln(os.Stderr, "erro: HIBP_API_KEY não definida")
		os.Exit(1)
	}

	cfg := Config{APIKey: *apiKey, Concurrency: *concurrency, Timeout: *timeout}
	results, err := ScanDomain(*domain, cfg)
	if err != nil {
		// Erros - stderr. stdout é sempre JSON válido.
		fmt.Fprintf(os.Stderr, "erro: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	enc.Encode(results)
}
