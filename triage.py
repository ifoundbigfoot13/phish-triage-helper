import os
from pydoc import text
import re
import json
import argparse
from datetime import datetime
from urllib.parse import urlparse

import requests


# ----------------------------
# Extraction helpers
# ----------------------------

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"https?://[^\s<>\")]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)

IGNORE_DOMAIN_PREFIXES = {
    "header.",
    "smtp.",
}

IGNORE_DOMAINS = {
    "corp.com",
}

def extract_ips(text: str) -> list[str]:
    return sorted(set(IP_RE.findall(text)))


def normalize_url(u: str) -> str:
    # Remove trailing punctuation common in copy/paste
    return u.rstrip(").,;!?:]'\"")


def extract_urls(text: str) -> list[str]:
    urls = [normalize_url(u) for u in URL_RE.findall(text)]
    # Deduplicate while keeping stable order
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


IGNORE_DOMAIN_PREFIXES = {
    "header.",
    "smtp.",
}

def is_valid_domain(d: str) -> bool:
    d = d.lower()

    # Remove obvious header field artifacts
    for prefix in IGNORE_DOMAIN_PREFIXES:
        if d.startswith(prefix):
            return False

    #Remove known internal domains
    if d in IGNORE_DOMAINS:
        return False
    
    # Require at least one dot and a TLD longer than 1 char
    parts = d.split(".")
    if len(parts) < 2:
        return False
    if len(parts[-1]) < 2:
        return False

    return True


def extract_domains(text: str) -> list[str]:
    raw_domains = set(DOMAIN_RE.findall(text))
    filtered = {d.lower() for d in raw_domains if is_valid_domain(d)}
    return sorted(filtered)


def domains_from_urls(urls: list[str]) -> list[str]:
    out = set()
    for u in urls:
        try:
            host = urlparse(u).hostname
            if host:
                out.add(host.lower())
        except Exception:
            pass
    return sorted(out)


# ----------------------------
# Threat Intel clients (optional)
# ----------------------------

def vt_headers() -> dict:
    api_key = os.getenv("VT_API_KEY", "").strip()
    if not api_key:
        return {}
    return {"x-apikey": api_key}


def abuse_headers() -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return {}
    return {"Key": api_key, "Accept": "application/json"}


def vt_url_id(url: str) -> str:
    # VirusTotal expects URL id as base64url of the URL without padding.
    import base64
    b = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return b.strip("=")


def vt_lookup_ip(ip: str) -> dict | None:
    h = vt_headers()
    if not h:
        return None
    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=h, timeout=15)
    if r.status_code != 200:
        return {"error": f"VT IP lookup failed ({r.status_code})", "body": safe_json(r)}
    return safe_json(r)


def vt_lookup_domain(domain: str) -> dict | None:
    h = vt_headers()
    if not h:
        return None
    r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=h, timeout=15)

    if r.status_code == 404:
        return {"not_found": True, "indicator": domain, "type": "domain"}
    if r.status_code != 200:
        return {"error": f"VT domain lookup failed ({r.status_code})", "body": safe_json(r)}

    return safe_json(r)


def vt_lookup_url(url: str) -> dict | None:
    h = vt_headers()
    if not h:
        return None
    url_id = vt_url_id(url)
    r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=h, timeout=15)

    if r.status_code == 404:
        return {"not_found": True, "indicator": url, "type": "url"}
    if r.status_code != 200:
        return {"error": f"VT URL lookup failed ({r.status_code})", "body": safe_json(r)}

    return safe_json(r)


def abuseipdb_check(ip: str) -> dict | None:
    h = abuse_headers()
    if not h:
        return None
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
    r = requests.get("https://api.abuseipdb.com/api/v2/check", headers=h, params=params, timeout=15)
    if r.status_code != 200:
        return {"error": f"AbuseIPDB lookup failed ({r.status_code})", "body": safe_json(r)}
    return safe_json(r)


def safe_json(resp: requests.Response) -> dict:
    try:
        return resp.json()
    except Exception:
        return {"raw_text": resp.text[:2000]}


# ----------------------------
# Link builders (always available, even without API keys)
# ----------------------------

def build_links(ips: list[str], domains: list[str], urls: list[str]) -> dict:
    links = {"ips": {}, "domains": {}, "urls": {}}

    for ip in ips:
        links["ips"][ip] = {
            "abuseipdb": f"https://www.abuseipdb.com/check/{ip}",
            "virustotal": f"https://www.virustotal.com/gui/ip-address/{ip}",
            "whois": f"https://who.is/whois-ip/ip-address/{ip}",
        }

    for d in domains:
        links["domains"][d] = {
            "virustotal": f"https://www.virustotal.com/gui/domain/{d}",
            "whois": f"https://who.is/whois/{d}",
            "urlscan_search": f"https://urlscan.io/search/#domain:{d}",
        }

    for u in urls:
        links["urls"][u] = {
            "virustotal": f"https://www.virustotal.com/gui/url/{vt_url_id(u)}",
            "urlscan_search": f"https://urlscan.io/search/#page.url:{u}",
        }

    return links


# ----------------------------
# Reporting
# ----------------------------

def summarize_vt(obj: dict) -> str:
    if not obj:
        return "VT: (no data)"
    if obj.get("not_found"):
        return "VT: not found (no record yet)"
    if "error" in obj:
        return f"VT: {obj['error']}"

    try:
        stats = obj["data"]["attributes"]["last_analysis_stats"]
        return (
            "VT stats: "
            f"harmless={stats.get('harmless')} "
            f"malicious={stats.get('malicious')} "
            f"suspicious={stats.get('suspicious')} "
            f"undetected={stats.get('undetected')}"
        )
    except Exception:
        return "VT: (unexpected response format)"

def summarize_abuse(obj: dict) -> str:
    if not obj:
        return "AbuseIPDB: (no data)"
    if "error" in obj:
        return f"AbuseIPDB: {obj['error']}"

    try:
        data = obj["data"]
        return (
            "AbuseIPDB: "
            f"score={data.get('abuseConfidenceScore')} "
            f"reports={data.get('totalReports')} "
            f"country={data.get('countryCode')}"
        )
    except Exception:
        return "AbuseIPDB: (unexpected response format)"

AUTH_FAIL_RE = re.compile(r"\b(spf|dkim|dmarc)=(fail|softfail)\b", re.IGNORECASE)

def count_auth_failures(text: str) -> int:
    return len(AUTH_FAIL_RE.findall(text))

def get_vt_malicious_count(vt_obj: dict | None) -> int | None:
    """
    Returns malicious count from VT last_analysis_stats if present.
    Returns None if VT data not available (missing key / not found / error).
    """
    if not vt_obj or vt_obj.get("not_found") or "error" in vt_obj:
        return None
    try:
        stats = vt_obj["data"]["attributes"]["last_analysis_stats"]
        m = stats.get("malicious")
        return int(m) if m is not None else None
    except Exception:
        return None

def get_abuse_score(abuse_obj: dict | None) -> int | None:
    if not abuse_obj or "error" in abuse_obj:
        return None
    try:
        score = abuse_obj["data"].get("abuseConfidenceScore")
        return int(score) if score is not None else None
    except Exception:
        return None

def analyst_assessment(text: str, extracted: dict, intel: dict) -> dict:
    """
    Very simple SOC-friendly scoring:
    - SPF/DKIM/DMARC fail signals increase risk
    - Any VT malicious detections increase risk
    - AbuseIPDB score increases risk
    """
    reasons = []
    actions = []

    auth_fails = count_auth_failures(text)
    if auth_fails:
        reasons.append(f"Authentication failures observed (SPF/DKIM/DMARC): {auth_fails} fail(s) detected")

    # Intel-based signals
    vt_mal_counts = []
    for ip, data in intel.get("ips", {}).items():
        vt_m = get_vt_malicious_count(data.get("virustotal"))
        if vt_m is not None:
            vt_mal_counts.append(vt_m)

    for d, data in intel.get("domains", {}).items():
        vt_m = get_vt_malicious_count(data.get("virustotal"))
        if vt_m is not None:
            vt_mal_counts.append(vt_m)

    for u, data in intel.get("urls", {}).items():
        vt_m = get_vt_malicious_count(data.get("virustotal"))
        if vt_m is not None:
            vt_mal_counts.append(vt_m)
        if data.get("virustotal") and data["virustotal"].get("not_found"):
            reasons.append("URL not found in VirusTotal (may be new/low prevalence)")

    max_vt_mal = max(vt_mal_counts) if vt_mal_counts else None
    if max_vt_mal is not None:
        if max_vt_mal >= 1:
            reasons.append(f"VirusTotal malicious detections observed (max malicious={max_vt_mal})")
        else:
            reasons.append("VirusTotal shows 0 malicious detections on queried indicators")

    abuse_scores = []
    for ip, data in intel.get("ips", {}).items():
        s = get_abuse_score(data.get("abuseipdb"))
        if s is not None:
            abuse_scores.append(s)
    max_abuse = max(abuse_scores) if abuse_scores else None
    if max_abuse is not None:
        if max_abuse >= 1:
            reasons.append(f"AbuseIPDB confidence score observed (max score={max_abuse})")
        else:
            reasons.append("AbuseIPDB confidence score is 0 for queried IPs")

    # Risk logic (simple, explainable)
    risk = "LOW"
    if (max_vt_mal is not None and max_vt_mal >= 1) or (max_abuse is not None and max_abuse >= 50):
        risk = "HIGH"
    elif auth_fails >= 1 or (max_abuse is not None and 1 <= max_abuse < 50):
        risk = "MEDIUM"

    # Suggested actions (SOC-style)
    actions.append("Review URL and sender domain in investigation links (VT/urlscan/WHOIS).")
    if extracted.get("urls"):
        actions.append("Detonate the URL in a safe sandbox (do not click directly).")
    if auth_fails:
        actions.append("If this is an internal user report, confirm the sender identity via known-good channel.")
    actions.append("If confirmed malicious, block sender domain/IP at email gateway and add to SIEM watchlist.")

    return {"risk": risk, "reasons": reasons, "actions": actions}

def write_markdown_report(out_path: str, extracted: dict, links: dict, intel: dict, raw_text: str):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = []
    lines.append(f"# Phishing Triage Report\n")
    lines.append(f"- Generated: {now}\n")

    lines.append("## Analyst Assessment\n")
    assessment = analyst_assessment(raw_text, extracted, intel)
    lines.append(f"**Risk Level:** {assessment['risk']}\n")

    if assessment["reasons"]:
        lines.append("**Why:**")
        for r in assessment["reasons"]:
            lines.append(f"- {r}")
    lines.append("")

    lines.append("**Recommended Actions:**")
    for a in assessment["actions"]:
        lines.append(f"- {a}")
    lines.append("")

    lines.append("## Extracted Indicators\n")

    lines.append(f"- IPs ({len(extracted['ips'])}): {', '.join(extracted['ips']) if extracted['ips'] else 'None'}")
    lines.append(f"- Domains ({len(extracted['domains'])}): {', '.join(extracted['domains']) if extracted['domains'] else 'None'}")
    lines.append(f"- URLs ({len(extracted['urls'])}): {len(extracted['urls']) if extracted['urls'] else 0}\n")

    if extracted["urls"]:
        lines.append("### URLs\n")
        for u in extracted["urls"]:
            lines.append(f"- {u}")
        lines.append("")

    lines.append("## Quick Links\n")

    if extracted["ips"]:
        lines.append("### IP Links\n")
        for ip, l in links["ips"].items():
            lines.append(f"- **{ip}**: [AbuseIPDB]({l['abuseipdb']}) | [VirusTotal]({l['virustotal']}) | [WHOIS]({l['whois']})")
        lines.append("")

    if extracted["domains"]:
        lines.append("### Domain Links\n")
        for d, l in links["domains"].items():
            lines.append(f"- **{d}**: [VirusTotal]({l['virustotal']}) | [WHOIS]({l['whois']}) | [urlscan search]({l['urlscan_search']})")
        lines.append("")

    if extracted["urls"]:
        lines.append("### URL Links\n")
        for u, l in links["urls"].items():
            lines.append(f"- **URL**: [VirusTotal]({l['virustotal']}) | [urlscan search]({l['urlscan_search']})")
            lines.append(f"  - {u}")
        lines.append("")

    lines.append("## Threat Intel (API Lookups)\n")
    lines.append("_If API keys are not configured, this section will be empty._\n")

    # IP intel
    if intel.get("ips"):
        lines.append("### IP Intelligence\n")
        for ip, data in intel["ips"].items():
            lines.append(f"- **{ip}**")
            if "abuseipdb" in data and data["abuseipdb"]:
                lines.append(f"  - {summarize_abuse(data['abuseipdb'])}")
            if "virustotal" in data and data["virustotal"]:
                lines.append(f"  - {summarize_vt(data['virustotal'])}")
        lines.append("")

    # Domain intel
    if intel.get("domains"):
        lines.append("### Domain Intelligence\n")
        for d, data in intel["domains"].items():
            lines.append(f"- **{d}**")
            if "virustotal" in data and data["virustotal"]:
                lines.append(f"  - {summarize_vt(data['virustotal'])}")
        lines.append("")

    # URL intel
    if intel.get("urls"):
        lines.append("### URL Intelligence\n")
        for u, data in intel["urls"].items():
            lines.append(f"- **URL**: {u}")
            if "virustotal" in data and data["virustotal"]:
                lines.append(f"  - {summarize_vt(data['virustotal'])}")
        lines.append("")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description="Phishing triage helper: extract indicators, generate links, and optionally query VT/AbuseIPDB.")
    parser.add_argument("--input", "-i", required=True, help="Path to a text file containing email headers (and optional body).")
    parser.add_argument("--out", "-o", default=None, help="Output report path (.md). Default: reports/triage_<timestamp>.md")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    ips = extract_ips(text)
    urls = extract_urls(text)

    raw_domains = set(extract_domains(text) + domains_from_urls(urls))

    # Final filtering pass (removes internal domains cleanly)
    domains = sorted(
        d for d in raw_domains
        if is_valid_domain(d)
    )

    extracted = {"ips": ips, "urls": urls, "domains": domains}
    links = build_links(ips, domains, urls)

    # Optional intel lookups
    intel = {"ips": {}, "domains": {}, "urls": {}}

    vt_enabled = bool(os.getenv("VT_API_KEY", "").strip())
    abuse_enabled = bool(os.getenv("ABUSEIPDB_API_KEY", "").strip())

    for ip in ips:
        intel["ips"][ip] = {
            "virustotal": vt_lookup_ip(ip) if vt_enabled else None,
            "abuseipdb": abuseipdb_check(ip) if abuse_enabled else None,
        }

    for d in domains:
        intel["domains"][d] = {
            "virustotal": vt_lookup_domain(d) if vt_enabled else None,
        }

    for u in urls:
        intel["urls"][u] = {
            "virustotal": vt_lookup_url(u) if vt_enabled else None,
        }

    # Output
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_path = args.out or f"reports/triage_{ts}.md"

    # Create reports dir if needed
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    write_markdown_report(out_path, extracted, links, intel, text)

    print(f"[+] Report written: {out_path}")
    print(f"[+] Extracted: ips={len(ips)} domains={len(domains)} urls={len(urls)}")
    if not vt_enabled:
        print("[!] VT_API_KEY not set; VirusTotal API lookups skipped (links still included).")
    if not abuse_enabled:
        print("[!] ABUSEIPDB_API_KEY not set; AbuseIPDB API lookups skipped (links still included).")


if __name__ == "__main__":
    main()