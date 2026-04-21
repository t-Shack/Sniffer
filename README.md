# SNIFFER — URL Threat Analyser

A terminal-grade phishing URL detection tool built with Go.
Combines local heuristic checks with VirusTotal's 70+ engine scan.

## Features

- IP-based URL detection (IPv4 and IPv6)
- Suspicious keyword matching
- URL length analysis
- VirusTotal API integration (70+ scanners)
- Dual mode: CLI and web interface
- Works offline (local checks run without internet)

## Requirements

- Go 1.22+
- VirusTotal API key (free at virustotal.com)

## Setup

**1. Clone the repository**
```bash
git clone https://github.com/t-Shack/Sniffer.git
cd sniffer
```

**2. Set your API key**

Windows (PowerShell):
```powershell
$env:VT_API_KEY = "your-api-key-here"
```

Linux / macOS:
```bash
export VT_API_KEY="your-api-key-here"
```

## Usage

**CLI mode**
```bash
go run main.go "https://example.com"
```

Example output:
✅ CLEAN — VirusTotal found no threats
⚠️  SUSPICIOUS — keyword matched: login
🚨 MALICIOUS — 4 engines flagged this URL


**Web mode**
```bash
go run main.go
```
Then open `http://localhost:8080` in your browser.

## How It Works

Each URL runs through four checks in order:

|     Check     |            Description                 | Works Offline |
|---------------|----------------------------------------|---------------|
| IP-based URL  | Flags raw IPv4/IPv6 addresses as hosts | Yes           |
| Keyword match | Detects phishing keywords in the URL   | Yes           |
| URL length    | Flags URLs over 75 characters          | Yes           |
| VirusTotal    | Queries 70+ security engines           | No            |

## Project Structure

sniffer/
├── main.go              # CLI + web server + detection logic
├── templates/
│   └── index.html       # Web UI (landing + dashboard)
└── README.md

## Built With

- [Go](https://go.dev) — backend + CLI
- [VirusTotal API v3](https://docs.virustotal.com) — threat intelligence
- Vanilla HTML/CSS/JS — web interface

## Version History

- v2.0 — Web UI + VirusTotal integration
- v1.0 — CLI tool with local heuristic checks

## Author

Built by Jude — Cybersecurity & Backend Software Engineer.
First shipped project.