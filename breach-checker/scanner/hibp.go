package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const hibpBase = "https://haveibeenpwned.com/api/v3"
const userAgent = "BreachChecker-Go/1.0"

func FetchBreachedEmails(domain string, cfg Config) ([]string, error) {
	client := &http.Client{Timeout: cfg.Timeout}
	req, _ := http.NewRequest("GET",
		fmt.Sprintf("%s/breacheddomain/%s", hibpBase, domain), nil)
	req.Header.Set("hibp-api-key", cfg.APIKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return []string{}, nil
	}
	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("chave API inválida")
	}
	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limit — reduz --concurrency")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var data map[string][]string
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &data)

	seen := map[string]bool{}
	var emails []string
	for _, aliases := range data {
		for _, alias := range aliases {
			email := alias + "@" + domain
			if !seen[email] {
				seen[email] = true
				emails = append(emails, email)
			}
		}
	}

	return emails, nil
}

func checkEmailHIBP(email string, apiKey string, timeout time.Duration) ([]string, error) {
	client := &http.Client{Timeout: timeout}
	req, _ := http.NewRequest("GET",
		fmt.Sprintf("%s/breachedaccount/%s", hibpBase, email), nil)
	req.Header.Set("hibp-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return []string{}, nil
	}
	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("chave API inválida")
	}
	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limit")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var breaches []struct {
		Name string `json:"Name"`
	}
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &breaches)

	names := make([]string, len(breaches))
	for i, b := range breaches {
		names[i] = b.Name
	}

	return names, nil
}
