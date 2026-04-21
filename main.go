package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
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

	if isIPBasedURL(rawURL) {
		return "⚠️  SUSPICIOUS — IP-based URL detected"
	}

	for _, keyword := range suspiciousKeywords {
		if strings.Contains(lower, keyword) {
			return "⚠️  SUSPICIOUS — keyword matched: " + keyword
		}
	}

	if len(rawURL) > 75 {
		return "⚠️  SUSPICIOUS — URL is unusually long"
	}
	return checkVirusTotal(rawURL)
}

func submitURL(rawURL string, apiKey string) (string, error) {

	formData := strings.NewReader("url=" + url.QueryEscape(rawURL))

	req, err := http.NewRequest("POST", "https://www.virustotal.com/api/v3/urls", formData)
	if err != nil {
		return "", err
	}

	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
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

// VTNumbers holds raw scan counts — used by both CLI and web
type VTNumbers struct {
	Malicious  int
	Suspicious int
	Harmless   int
}

func fetchAnalysis(analysisID string, apiKey string) (*VTNumbers, error) {
	req, err := http.NewRequest("GET", "https://www.virustotal.com/api/v3/analyses/"+analysisID, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format")
	}

	attributes, ok := data["attributes"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("attributes not found")
	}

	stats, ok := attributes["stats"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("stats not found")
	}

	return &VTNumbers{
		Malicious:  int(stats["malicious"].(float64)),
		Suspicious: int(stats["suspicious"].(float64)),
		Harmless:   int(stats["harmless"].(float64)),
	}, nil
}

func checkVirusTotal(rawURL string) string {
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		return "⚠️  VT check skipped — no API key found"
	}
	analysisID, err := submitURL(rawURL, apiKey)
	if err != nil {
		return "⚠️  VT check failed — " + err.Error()
	}
	nums, err := fetchAnalysis(analysisID, apiKey)
	if err != nil {
		return "⚠️  VT fetch failed — " + err.Error()
	}
	if nums.Malicious > 0 {
		return fmt.Sprintf("🚨 MALICIOUS — %d engines flagged this URL", nums.Malicious)
	}
	if nums.Suspicious > 0 {
		return fmt.Sprintf("⚠️  SUSPICIOUS — %d engines flagged this URL", nums.Suspicious)
	}
	return "✅ CLEAN — VirusTotal found no threats"
}

// ── Web layer ────────────────────────────────────────────────────────────────

type CheckItem struct {
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
	Flag   string `json:"flag"` // "ok", "warn", "bad"
}

type ScanResult struct {
	IPCheck      CheckItem `json:"ip_check"`
	KeywordCheck CheckItem `json:"keyword_check"`
	LengthCheck  CheckItem `json:"length_check"`
	VTFlagged    int       `json:"vt_flagged"`
	VTClean      int       `json:"vt_clean"`
	VTDetail     string    `json:"vt_detail"`
	VTFlag       string    `json:"vt_flag"`
	Verdict      string    `json:"verdict"`
	Risk         string    `json:"risk"`
	Error        string    `json:"error,omitempty"`
}

func analyzeURL(rawURL string) ScanResult {
	r := ScanResult{}
	lower := strings.ToLower(rawURL)

	// IP check
	if isIPBasedURL(rawURL) {
		r.IPCheck = CheckItem{false, "raw ip address detected", "bad"}
	} else {
		r.IPCheck = CheckItem{true, "no ip-based url pattern", "ok"}
	}

	// Keyword check
	foundKw := ""
	for _, kw := range suspiciousKeywords {
		if strings.Contains(lower, kw) {
			foundKw = kw
			break
		}
	}
	if foundKw != "" {
		r.KeywordCheck = CheckItem{false, `"` + foundKw + `" detected in url`, "warn"}
	} else {
		r.KeywordCheck = CheckItem{true, "no suspicious keywords found", "ok"}
	}

	// Length check
	if len(rawURL) > 75 {
		r.LengthCheck = CheckItem{false, fmt.Sprintf("%d chars — exceeds threshold", len(rawURL)), "warn"}
	} else {
		r.LengthCheck = CheckItem{true, fmt.Sprintf("%d chars — within normal range", len(rawURL)), "ok"}
	}

	// VT check
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		r.VTDetail = "api key not found — skipped"
		r.VTFlag = "warn"
	} else {
		id, err := submitURL(rawURL, apiKey)
		if err != nil {
			r.VTDetail = "error: " + err.Error()
			r.VTFlag = "warn"
		} else {
			nums, err := fetchAnalysis(id, apiKey)
			if err != nil {
				r.VTDetail = "fetch error: " + err.Error()
				r.VTFlag = "warn"
			} else {
				r.VTFlagged = nums.Malicious
				r.VTClean = nums.Harmless
				if nums.Malicious > 0 {
					r.VTDetail = fmt.Sprintf("%d engines detected threat", nums.Malicious)
					r.VTFlag = "bad"
				} else if nums.Suspicious > 0 {
					r.VTDetail = fmt.Sprintf("%d engines marked suspicious", nums.Suspicious)
					r.VTFlag = "warn"
				} else {
					r.VTDetail = "all scanners returned clean"
					r.VTFlag = "ok"
				}
			}
		}
	}

	// Verdict
	if !r.IPCheck.Passed || r.VTFlagged > 2 {
		r.Verdict = "MALICIOUS — do not visit this url"
		r.Risk = "HIGH"
	} else if !r.KeywordCheck.Passed || !r.LengthCheck.Passed || r.VTFlagged > 0 {
		r.Verdict = "SUSPICIOUS — proceed with caution"
		r.Risk = "MEDIUM"
	} else {
		r.Verdict = "CLEAN — no threats detected"
		r.Risk = "LOW"
	}

	return r
}

var tmpl *template.Template

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if err := tmpl.ExecuteTemplate(w, "index.html", nil); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.URL == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ScanResult{Error: "invalid or missing url"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(analyzeURL(body.URL))
}

func startServer() {
	var err error
	tmpl, err = template.ParseFiles("templates/index.html")
	if err != nil {
		log.Fatal("could not load template: ", err)
	}
	http.HandleFunc("/", serveIndex)
	http.HandleFunc("/check", handleCheck)
	fmt.Println("╔══════════════════════════════════╗")
	fmt.Println("║  SNIFFER // URL Threat Analyser  ║")
	fmt.Println("║  running at http://localhost:8080 ║")
	fmt.Println("║  Ctrl+C to stop                  ║")
	fmt.Println("╚══════════════════════════════════╝")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func main() {
	if len(os.Args) < 2 {
		// No args → web mode
		startServer()
	} else {
		// Args provided → CLI mode (unchanged)
		fmt.Println(checkURL(os.Args[1]))
	}
}
