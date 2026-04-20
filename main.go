package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var suspiciousKeywords = []string{
	"login", "verify", "update", "secure", "account",
	"banking", "confirm", "password", "signin", "support",
}

func isIPBasedURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	host := parsed.Hostname()
	return net.ParseIP(host) != nil
}

func checkURL(rawURL string) string {
	lower := strings.ToLower(rawURL)

	// Check 1: IP-based URL
	// Phishing URLs often use raw IPs instead of domain names
	if isIPBasedURL(rawURL) {
		return "⚠️  SUSPICIOUS — IP-based URL detected"
	}

	// Check 2: Suspicious keywords
	for _, keyword := range suspiciousKeywords {
		if strings.Contains(lower, keyword) {
			return "⚠️  SUSPICIOUS — keyword matched: " + keyword
		}
	}

	// Check 3: URL length
	if len(rawURL) > 75 {
		return "⚠️  SUSPICIOUS — URL is unusually long"
	}

	// Check 4: VirusTotal API
	vtResult := checkVirusTotal(rawURL)
	return vtResult
}

func checkVirusTotal(rawURL string) string {
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		return "⚠️  VT check skipped — no API key found"
	}

	// Step 1: Submit URL for scanning
	analysisID, err := submitURL(rawURL, apiKey)
	if err != nil {
		return "⚠️  VT check failed — " + err.Error()
	}

	// Step 2: Fetch results using analysis ID
	result, err := fetchAnalysis(analysisID, apiKey)
	if err != nil {
		return "⚠️  VT fetch failed — " + err.Error()
	}

	return result
}

func submitURL(rawURL string, apiKey string) (string, error) {
	// Encode the URL as form data
	formData := strings.NewReader("url=" + url.QueryEscape(rawURL))

	req, err := http.NewRequest("POST", "https://www.virustotal.com/api/v3/urls", formData)
	if err != nil {
		return "", err
	}

	// Set required headers
	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("accept", "application/json")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Parse JSON to extract analysis ID
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	// Check if VT returned an error
	if errObj, hasError := result["error"].(map[string]interface{}); hasError {
		msg, _ := errObj["message"].(string)
		return "", fmt.Errorf("VirusTotal error: %s", msg)
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("unexpected response format")
	}

	id, ok := data["id"].(string)
	if !ok {
		return "", fmt.Errorf("analysis ID not found")
	}

	return id, nil
}

func fetchAnalysis(analysisID string, apiKey string) (string, error) {
	req, err := http.NewRequest("GET", "https://www.virustotal.com/api/v3/analyses/"+analysisID, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	// Check if VT returned an error
	if errObj, hasError := result["error"].(map[string]interface{}); hasError {
		msg, _ := errObj["message"].(string)
		return "", fmt.Errorf("VirusTotal error: %s", msg)
	}

	// Drill into: data -> attributes -> stats
	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("unexpected response format")
	}

	attributes, ok := data["attributes"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("attributes not found")
	}

	stats, ok := attributes["stats"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("stats not found")
	}

	// Extract what we care about
	malicious := int(stats["malicious"].(float64))
	suspicious := int(stats["suspicious"].(float64))

	if malicious > 0 {
		return fmt.Sprintf("🚨 MALICIOUS — %d engines flagged this URL", malicious), nil
	}
	if suspicious > 0 {
		return fmt.Sprintf("⚠️  SUSPICIOUS — %d engines flagged this URL", suspicious), nil
	}

	return "✅ CLEAN — VirusTotal found no threats", nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: Sniffer <url>")
		os.Exit(1)
	}

	url := os.Args[1]
	result := checkURL(url)
	fmt.Println(result)
}
