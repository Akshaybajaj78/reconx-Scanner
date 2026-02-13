# ReconX CLI

Terminal-based automated reconnaissance and vulnerability scanner for academic use.

## Features
- Port scanning (top 1000 ports via nmap)
- Subdomain scanning (small built-in wordlist)
- Directory scanning (from `wordlist.txt`)
- HTTP header security checks
- CORS misconfiguration checks
- Basic XSS reflection test
- PDF report generation

## Setup
1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Ensure Nmap is installed and available in your PATH.

## Run
```bash
python reconx.py example.com
```

## Run Web UI
```bash
python app.py
```
Then open `http://127.0.0.1:5000` in your browser.

Optional arguments:
- `--wordlist path/to/wordlist.txt`
- `--report reconx_report.pdf`
- `--timeout 5`

## Notes
- This tool is intended for academic, authorized testing only.
- Some scans may require permissions or be blocked by target defenses.
