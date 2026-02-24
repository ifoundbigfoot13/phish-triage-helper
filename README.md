# Phish Triage Helper

A small SOC triage helper that:
- parses an email header/body dump
- extracts IPs, domains, and URLs
- generates investigation links (VirusTotal, AbuseIPDB, urlscan.io, WHOIS)
- optionally enriches indicators via API keys
- outputs a Markdown report you can attach to a ticket
- includes an analyst-style risk assessment (LOW/MEDIUM/HIGH) with recommended actions

## Project Structure
- `triage.py` – main script
- `requirements.txt` – dependencies
- `samples/` – sanitized sample input
- `reports/` – generated output
- `.env.example` – environment variable template

## Install (Powershell)
```
py -m pip install -r requirements.txt
#Run (no API keys required)
py triage.py --input samples/email.txt
```
A report will be written to:
`reports/triage_YYYYMMDD_HHMMSS.md`

### Optional: Enable API enrichment (PowerShell)

In the same terminal session:
```
$env:VT_API_KEY="YOUR_VT_KEY"
$env:ABUSEIPDB_API_KEY="YOUR_ABUSEIPDB_KEY"
py triage.py --input samples/email.txt`
```
## Example Report

`screenshot-report.png`
