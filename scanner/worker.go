package main

import (
	"sync"
	"time"
)

type Config struct {
	APIKey      string
	Concurrency int
	Timeout     time.Duration
}

type ScanResult struct {
	Email       string   `json:"email"`
	Breaches    []string `json:"breaches"`
	BreachCount int      `json:"breaches_count"`
	Error       string   `json:"error,omitempty"`
}

type DomainReport struct {
	Domain      string       `json:"domain"`
	ScannedAt   time.Time    `json:"scanned_at"`
	TotalEmails int          `json:"total_emails"`
	Compromised int          `json:"compromised"`
	Results     []ScanResult `json:"results"`
}

func ScanDomain(domain string, cfg Config) (*DomainReport, error) {
	emails, err := FetchBreachedEmails(domain, cfg)
	if err != nil {
		return nil, err
	}

	//Semaforo: máximo cfg.Concurrency goroutines activas
	sem := make(chan struct{}, cfg.Concurrency)
	results := make([]ScanResult, len(emails))
	var wg sync.WaitGroup

	for i, email := range emails {
		wg.Add(1)
		go func(idx int, e string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = checkSingleEmail(e, cfg)
		}(i, email)
	}

	wg.Wait()

	compromised := 0
	for _, r := range results {
		if r.BreachCount > 0 {
			compromised++
		}
	}

	return &DomainReport{
		Domain:      domain,
		ScannedAt:   time.Now().UTC(),
		TotalEmails: len(emails),
		Compromised: compromised,
		Results:     results,
	}, nil
}

func checkSingleEmail(email string, cfg Config) ScanResult {
	// Implementação simplificada - chama API HIBP
	breaches, err := checkEmailHIBP(email, cfg.APIKey, cfg.Timeout)
	if err != nil {
		return ScanResult{
			Email: email,
			Error: err.Error(),
		}
	}

	return ScanResult{
		Email:       email,
		Breaches:    breaches,
		BreachCount: len(breaches),
	}
}
