<div align="center">

# ThreatLens 🔍
### Threat Intelligence & Vulnerability Scanner

> A modular, professional-grade security reconnaissance tool built in Python.  
> It Performs OSINT, port scanning, SSL analysis, header inspection, DNS checks, tech fingerprinting and CVE lookup, **all in parallel**.
> It also generates a structured PDF + HTML report with a risk score.

</div>

---

## What it does

ThreatLens takes a domain or IP address and runs a full security assessment automatically:

1. **Validates and sanitises** the input against shell injection
2. **Runs 5 scans in parallel** - nmap, theHarvester, testssl, header checker, DNS/WHOIS, fingerprinting
3. **Runs CVE lookup** against the NVD database using discovered version info
4. **Correlates findings** across all tools using 11 cross-tool threat patterns
5. **Calculates a risk score** out of 100 with severity breakdown
6. **Generates reports** — Rich terminal UI, PDF, HTML, and raw JSON

---

## Features

| Module                   | What it checks                                                    |
|--------------------------|-------------------------------------------------------------------|
| **OSINT**                | Subdomains, emails, IP addresses via theHarvester                 |
| **Port Scanner**         | Open ports, services, versions via nmap                           |
| **SSL/TLS**              | Weak protocols, POODLE, HEARTBLEED, cert expiry via testssl       |
| **Header Checker**       | CSP, HSTS, X-Frame-Options, leaky server headers                  |
| **DNS / WHOIS**          | SPF, DMARC, DKIM, domain age, registrar info                      |
| **Tech Fingerprinting**  | CMS (WordPress, Joomla, Drupal), frameworks, server software      |
| **CVE Lookup**           | Queries NVD API for CVEs matching discovered versions             |
| **Correlation Engine**   | 11 cross-tool patterns (e.g. weak SSL + open HTTPS = active risk) |
| **Risk Scoring**         | Weighted severity scoring, capped at 100                          |
| **Report Generator**     | PDF (ReportLab), HTML, JSON, Rich terminal summary                |

---

## Project Structure

```
ThreatLens/
├── main.py                      # Entry point — orchestrates the pipeline
├── modules/
│   ├── scanner.py               # nmap port scanner
│   ├── osint.py                 # theHarvester OSINT
│   ├── misconfig.py             # testssl SSL/TLS check
│   ├── headers.py               # HTTP security header checker
│   ├── dns_whois.py             # SPF, DMARC, DKIM, WHOIS
│   ├── fingerprint.py           # CMS and tech fingerprinting
│   ├── cve_lookup.py            # NVD CVE lookup
│   ├── correlation.py           # Cross-tool threat correlation
│   ├── scoring.py               # Risk scoring engine
│   └── parallel_runner.py       # ThreadPoolExecutor parallel runner
├── reports/
│   ├── report_generator.py      # HTML report
│   ├── pdf_generator.py         # PDF report (ReportLab)
│   └── terminal_output.py       # Rich terminal UI
├── utils/
│   └── validation.py            # Input validation and sanitisation
├── output/                      # Generated reports saved here
│   ├── report.html
│   ├── report.pdf
│   └── raw_results.json
└── tests/
    └── test_validation.py
```

---

## How the pipeline works

```
User Input
    ↓
validate_input() + sanitise_target()
    ↓
┌─────────────────────────────────────────────────────┐
│              Parallel (ThreadPoolExecutor)           │
│  nmap │ theHarvester │ testssl │ headers │ dns/whois │ fingerprint │
└─────────────────────────────────────────────────────┘
    ↓
CVE Lookup (sequential — needs nmap + fingerprint output)
    ↓
correlate_findings()  ← 11 cross-tool threat patterns
    ↓
calculate_risk()      ← weighted scoring, capped at 100
    ↓
┌──────────────────────────────────┐
│  report.html │ report.pdf │ JSON │
└──────────────────────────────────┘
    ↓
Rich terminal summary + download prompt
```

---

## Installation

### Requirements

- Python 3.10+
- Kali Linux or any Linux distro
- nmap
- theHarvester
- testssl.sh

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/ThreatLens.git
cd ThreatLens

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install requests dnspython whois reportlab rich

# Verify external tools are installed
nmap --version
theHarvester --version
testssl.sh --version
```

---

## Usage

```bash
# Activate venv first (every new terminal session)
source venv/bin/activate

# Run the scanner
python main.py

# Enter target when prompted
Enter target (domain/IP): scanme.nmap.org
```

### Legal test targets

| Target | Purpose |
|---|---|
| `scanme.nmap.org` | Maintained by nmap team — explicitly permitted |
| `testphp.vulnweb.com` | Acunetix test site — deliberately vulnerable |
| `http.badssl.com` | SSL/header testing — publicly available |

> ⚠️ **Only scan targets you own or have explicit written permission to scan.**  
> Unauthorised scanning is illegal in most jurisdictions.

---

## Output

After each scan the following files are saved to `output/`:

| File               | Format | Purpose                               |
|--------------------|--------|---------------------------------------|
| `report.pdf`       | PDF    | Professional client-ready report      |
| `report.html`      | HTML   | Open in browser for full styled view  |
| `raw_results.json` | JSON   | Machine-readable data for integration |

---

## Correlation Patterns

The correlation engine detects combined threats that no single tool can catch alone:

| Pattern                              | Tools Combined          | Severity |
|--------------------------------------|-------------------------|----------|
| Exposed admin port                   | nmap                    | High     |
| Weak SSL + open HTTPS                | nmap + testssl          | High     |
| Emails + subdomains exposed          | theHarvester            | Medium   |
| Unencrypted service + sensitive port | nmap                    | High     |
| Cert trust issue + live HTTPS        | testssl + nmap          | Medium   |
| Poor headers + HTTP open             | headers + nmap          | High     |
| Young domain + email exposure        | whois + osint           | Critical |
| No SPF + No DMARC                    | dns                     | Critical |
| CMS detected + many open ports       | fingerprint + nmap      | High     |
| Server version exposed + weak SSL    | fingerprint + testssl   | High     |
| Critical CVE + exposed service       | nvd + nmap              | Critical |

---

## Risk Scoring

| Score     | Severity  |
|-----------|-----------|
| 75 – 100  | Critical  |
| 50 – 74   | High      |
| 25 – 49   | Medium    |
| 0 – 24    | Low       |

Severity weights: Critical = 40pts, High = 25pts, Medium = 15pts, Low = 5pts  
Final score is capped at 100.

---

## Built with

- Python 3.13
- [Rich](https://github.com/Textualize/rich) — terminal UI
- [ReportLab](https://www.reportlab.com/) — PDF generation
- [dnspython](https://www.dnspython.org/) — DNS queries
- [requests](https://requests.readthedocs.io/) — HTTP client
- [nmap](https://nmap.org/) — port scanning
- [theHarvester](https://github.com/laramies/theHarvester) — OSINT
- [testssl.sh](https://testssl.sh/) — SSL/TLS analysis
- [NVD API](https://nvd.nist.gov/developers/vulnerabilities) — CVE data

---

## Learning notes

This project was built as a hands-on cybersecurity learning exercise. Every module was written incrementally with a focus on understanding. Key concepts learned and applied:

- Subprocess management and output parsing
- XML parsing (nmap -oX output)
- Parallel execution with ThreadPoolExecutor
- DNS record types (TXT, MX, SPF, DMARC, DKIM)
- HTTP security headers and their attack vectors
- CVSS scoring system
- Shell injection prevention via input sanitisation
- Virtual environment isolation on Kali Linux
- Professional report generation (PDF + HTML)

---

## Disclaimer

ThreatLens is intended for **authorised security testing only**.  
The author is not responsible for any misuse of this tool.  
Always obtain written permission before scanning any target.
---

*Built by Alissa — cybersecurity learner*
