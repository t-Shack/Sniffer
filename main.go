package main

import (
	"fmt"
	"net"
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

	return "✅ LOOKS CLEAN — no obvious red flags"
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
