# ReconX: Advanced Vulnerability Intelligence Scanner

ReconX is a comprehensive, fast, and modular Python-based tool designed for deep reconnaissance and automated vulnerability assessment. It integrates and automates various penetration testing techniques to provide a unified framework for security engineers.

---

## 🔥 Core Capabilities

- **Technology Fingerprinting**: Detects CMSs, frameworks, plugins, themes, server software, and OS with version extraction.
- **Endpoint Discovery**: Crawls sites, brute-forces paths, and parses JavaScript for API endpoints.
- **Vulnerability Matching**: Compares detected versions against Exploit-DB, CVE/CVSS databases, and Vulners API.
- **Subdomain Enumeration & Asset Discovery**: Utilizes techniques for subdomain discovery and performs port scanning on discovered assets.
- **Built-in Fuzzing Engine**: Customizable payloads for common vulnerabilities like RCE, SQLi, LFI, XSS, and Open Redirects.
- **SSL & Security Header Analysis**: Checks for outdated TLS, weak ciphers, insecure headers, CSP, and CORS misconfigurations.
- **Plugin-based Architecture**: Easily extendable with new modules for specific technologies (e.g., WordPress, Joomla, Laravel, Flask).

---

## ⚡ Speed & Performance

ReconX is built for speed, leveraging:

- Multithreading and asynchronous operations (`asyncio`, `httpx`)
- Intelligent caching of responses
- Parallel execution of scanning and fingerprinting tasks

---

## 📦 Output & Reporting

Generates detailed, structured reports in:

- **HTML**: For interactive and visually appealing summaries.
- **JSON**: For programmatic integration and machine readability.
- **Plain Text**: For quick console review.

Reports are sorted by severity, providing clear status indicators and export options.

---

## 🛠️ Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/ReconX.git
cd ReconX
```

Create a virtual environment (recommended):

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🧪 Usage

ReconX is a command-line tool.

```bash
python reconx.py -u <target_url> [options]
```

### Examples:

**Basic Scan:**

```bash
python reconx.py -u https://example.com
```

**Deep Scan with HTML Report:**

```bash
python reconx.py -u https://example.com --deep-crawl -o report.html --output-format html
```

**Scan with Subdomain Enumeration and Port Scan, verbose output:**

```bash
python reconx.py -u https://example.com --include-subdomains --port-scan -v
```

**Scan with Fuzzing and JSON Output:**

```bash
python reconx.py -u https://example.com --fuzz -o results.json --output-format json
```

**Only report vulnerabilities:**

```bash
python reconx.py -u https://example.com --only-vuln
```

---

### Command-Line Arguments

| Argument | Description |
|----------|-------------|
| `-u, --url <target_url>` | **Required.** The target URL to scan (e.g., https://example.com) |
| `-o, --output-file <path>` | Path to save the report file (e.g., report.html) |
| `--output-format <format>` | Report format (`html`, `json`, `text`). Default: `html` |
| `-v, --verbose` | Enable verbose output for detailed logging |
| `--fast` | Perform a faster scan (skips deep crawling, extensive port scans) |
| `--deep-crawl` | Enable deep crawling for endpoint discovery |
| `--include-subdomains` | Include subdomain enumeration in the scan |
| `--port-scan` | Perform port scanning on discovered assets |
| `--plugins <list>` | Comma-separated list of specific plugins to run (e.g., `wordpress,joomla`) or `all`. Default: `all` |
| `--only-vuln` | Only report identified vulnerabilities, suppressing other information |
| `--compare-cve` | Compare detected versions with CVE databases (enabled by default if vulnerability matching is active) |
| `--fuzz` | Enable fuzzing for common vulnerabilities (XSS, SQLi, LFI, RCE, Open Redirect) |

---

## 🧠 Intelligence & Extensibility

ReconX is designed to be extensible:

- **Plugin System**: Easily add new technology-specific checks.
- **Integration Modules**: Seamlessly connect with external APIs like Vulners, Exploit-DB, Shodan, Censys, and FOFA.
- **Data-Driven**: Utilizes local fingerprint databases and optional CVE caches for offline mode.

---

## 🤝 Contributing

We welcome contributions! Please refer to the `CONTRIBUTING.md` (to be created) for guidelines on how to contribute to ReconX.

---

## 📄 License

This project is licensed under the MIT License - see the `LICENSE` file (to be created) for details.
