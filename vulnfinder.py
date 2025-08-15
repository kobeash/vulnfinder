#!/usr/bin/env python3
"""
vulnfinder.py - Aggregates public vulnerabilities for a product+version.
Features:
- OSV (Open Source Vulnerabilities)
- NVD (National Vulnerability Database) with CVSS & exploitability
- Local searchsploit (optional)
- JSON / CSV output
- Clean CLI table using Rich
"""

from __future__ import annotations
import argparse
import os
import json
import csv
import time
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
import requests
from rich.console import Console
from rich.table import Table

# ---------------------------
# Config
# ---------------------------
OSV_API = "https://api.osv.dev/v1/query"
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PATH = Path.home() / ".vulnfinder_cache.json"
CACHE_TTL_HOURS = 12

console = Console()

# ---------------------------
# Simple JSON cache
# ---------------------------
def load_cache() -> dict:
    if not CACHE_PATH.exists():
        return {}
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_cache(cache: dict):
    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass

def cache_get(key: str):
    cache = load_cache()
    entry = cache.get(key)
    if not entry:
        return None
    ts = datetime.fromisoformat(entry.get("_ts"))
    if datetime.utcnow() - ts > timedelta(hours=CACHE_TTL_HOURS):
        cache.pop(key, None)
        save_cache(cache)
        return None
    return entry.get("value")

def cache_set(key: str, value):
    cache = load_cache()
    cache[key] = {"_ts": datetime.utcnow().isoformat(), "value": value}
    save_cache(cache)

# ---------------------------
# OSV query
# ---------------------------
def query_osv(product: str, version: str | None):
    key = f"osv:{product}:{version or ''}"
    cached = cache_get(key)
    if cached is not None:
        return cached

    purl = f"pkg:generic/{product.lower().replace(' ', '_')}"
    payload = {"package": {"purl": purl}}
    if version:
        payload["version"] = version

    try:
        r = requests.post(OSV_API, json=payload, timeout=15)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulns", []) or []
        out = []
        for v in vulns:
            cvss_score = None
            severity = None
            for sev in v.get("severity", []):
                if sev.get("type") in ["CVSS_V3", "CVSSv3"]:
                    cvss_score = float(sev.get("score", 0))
                    if cvss_score >= 9:
                        severity = "Critical"
                    elif cvss_score >= 7:
                        severity = "High"
                    elif cvss_score >= 4:
                        severity = "Medium"
                    else:
                        severity = "Low"
                    break
            out.append({
                "id": v.get("id"),
                "summary": v.get("summary") or (v.get("details") or "")[:400],
                "published": v.get("published"),
                "cvss_score": cvss_score,
                "severity": severity,
                "exploitability": "Unknown",
                "references": [ref.get("url") for ref in v.get("references", []) if ref.get("url")]
            })
        cache_set(key, out)
        return out
    except Exception:
        return []

# ---------------------------
# Helpers
# ---------------------------
def find_cpe_strings(obj):
    results = set()
    if isinstance(obj, dict):
        for v in obj.values():
            results |= find_cpe_strings(v)
    elif isinstance(obj, list):
        for item in obj:
            results |= find_cpe_strings(item)
    elif isinstance(obj, str):
        if obj.startswith("cpe:2.3:"):
            results.add(obj)
    return results

# ---------------------------
# NVD query
# ---------------------------
def search_nvd(product: str, version: str | None):
    key = f"nvd:{product}:{version or ''}"
    cached = cache_get(key)
    if cached is not None:
        return cached

    apikey = os.getenv("NVD_API_KEY")
    headers = {"apiKey": apikey} if apikey else {}
    query = f"{product} {version}" if version else product
    params = {"keywordSearch": query, "resultsPerPage": 200}

    try:
        r = requests.get(NVD_CPE_API, params=params, headers=headers, timeout=20)
        r.raise_for_status()
        data = r.json()
        products = data.get("products") or []
        cpe_candidates = set()
        for p in products:
            cpe_candidates |= find_cpe_strings(p)
        if not cpe_candidates and version:
            params2 = {"keywordSearch": product, "resultsPerPage": 200}
            r2 = requests.get(NVD_CPE_API, params=params2, headers=headers, timeout=20)
            if r2.ok:
                for p in (r2.json().get("products") or []):
                    cpe_candidates |= find_cpe_strings(p)

        cves = {}
        for cpe in sorted(cpe_candidates):
            params = {"cpeName": cpe, "resultsPerPage": 2000}
            try:
                rcv = requests.get(NVD_CVE_API, params=params, headers=headers, timeout=20)
                if rcv.status_code != 200:
                    continue
                j = rcv.json()
                for vuln in j.get("vulnerabilities", []):
                    cve_obj = vuln.get("cve", {})
                    cve_id = cve_obj.get("id") or cve_obj.get("CVE_data_meta", {}).get("ID") or vuln.get("cveId")
                    desc = ""
                    for d in cve_obj.get("descriptions", []) if isinstance(cve_obj.get("descriptions"), list) else []:
                        if d.get("lang") == "en":
                            desc = d.get("value") or ""
                            break
                    if not desc:
                        desc = (cve_obj.get("descriptions") or "") if isinstance(cve_obj.get("descriptions"), str) else desc
                    refs = []
                    if isinstance(cve_obj.get("references"), list):
                        for rref in cve_obj.get("references"):
                            href = rref.get("url") or rref.get("reference_data", {}).get("url")
                            if href:
                                refs.append(href)
                    # CVSS severity
                    severity = None
                    cvss_score = None
                    metrics = cve_obj.get("metrics", {})
                    exploitability = "Unknown"
                    if "cvssMetricV31" in metrics:
                        cvss = metrics["cvssMetricV31"][0]["cvssData"]
                        cvss_score = float(cvss.get("baseScore", 0))
                        if cvss_score >= 9: severity = "Critical"
                        elif cvss_score >= 7: severity = "High"
                        elif cvss_score >= 4: severity = "Medium"
                        else: severity = "Low"
                        av = cvss.get("attackVector")
                        ac = cvss.get("attackComplexity")
                        if av == "NETWORK" and ac == "LOW":
                            exploitability = "Easy"
                        else:
                            exploitability = "Moderate/Hard"
                    if cve_id:
                        cves[cve_id] = {
                            "id": cve_id,
                            "description": desc,
                            "references": refs,
                            "severity": severity,
                            "cvss_score": cvss_score,
                            "exploitability": exploitability
                        }
                time.sleep(0.15)
            except Exception:
                continue
        out = list(cves.values())
        cache_set(key, out)
        return out
    except Exception:
        return []

# ---------------------------
# searchsploit
# ---------------------------
def run_searchsploit(product: str, version: str | None):
    prog = shutil.which("searchsploit")
    if not prog:
        return None, "searchsploit not found"
    query = product + ((" " + version) if version else "")
    try:
        p = subprocess.run([prog, "--color", "never", query], capture_output=True, text=True, timeout=20)
        out = p.stdout.strip()
        return out.splitlines() if out else [], ""
    except Exception as e:
        return None, str(e)

# ---------------------------
# CLI table printing
# ---------------------------
def print_table(source_name: str, items):
    if not items:
        console.print(f"[{source_name}] No results found.")
        return
    table = Table(title=f"{source_name} vulnerabilities")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="red")
    table.add_column("Exploitability", style="green")
    table.add_column("Description")
    for it in items:
        table.add_row(
            it.get("id") or "?",
            it.get("severity") or "-",
            it.get("exploitability") or "-",
            (it.get("summary") or it.get("description") or "")[:100]
        )
    console.print(table)

# ---------------------------
# CSV Output
# ---------------------------
def save_csv(filename: str, results: dict):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["source","id","severity","cvss_score","exploitability","description","references"])
        for source, items in results["sources"].items():
            for it in items:
                writer.writerow([
                    source,
                    it.get("id") or "",
                    it.get("severity") or "",
                    it.get("cvss_score") or "",
                    it.get("exploitability") or "",
                    it.get("summary") or it.get("description") or "",
                    ", ".join(it.get("references") or [])
                ])
    console.print(f"[CSV] Saved to {filename}")

# ---------------------------
# CLI
# ---------------------------
def main():
    ap = argparse.ArgumentParser(description="VulnFinder: product and version specified separately")
    ap.add_argument("product", help="Product name (e.g., apache, openssh)")
    ap.add_argument("version", nargs="?", default=None, help="Product version (optional)")
    ap.add_argument("-e", "--exploits", action="store_true", help="Run local searchsploit")
    ap.add_argument("-j", "--json", action="store_true", help="Emit JSON")
    ap.add_argument("-c", "--csv", help="Save CSV output")
    args = ap.parse_args()

    product = args.product.strip()
    version = args.version.strip() if args.version else None
    console.print(f"Searching vulnerabilities for: product='{product}' version='{version or 'any'}' ...")

    results = {"query": {"product": product, "version": version}, "timestamp": datetime.utcnow().isoformat(), "sources": {}}

    osv = query_osv(product, version)
    results["sources"]["osv"] = osv
    print_table("OSV", osv)

    nvd = search_nvd(product, version)
    results["sources"]["nvd"] = nvd
    print_table("NVD", nvd)

    if args.exploits:
        ss_out, ss_err = run_searchsploit(product, version)
        if ss_out is None:
            console.print(f"[searchsploit] Error: {ss_err}")
            results["sources"]["searchsploit_error"] = ss_err
        else:
            results["sources"]["searchsploit"] = ss_out
            table = Table(title="searchsploit raw output")
            table.add_column("Line")
            for line in ss_out[:20]:
                table.add_row(line)
            if len(ss_out) > 20:
                table.add_row("...")
            console.print(table)

    if args.json:
        print(json.dumps(results, indent=2))
    if args.csv:
        save_csv(args.csv, results)

    console.print("\nDone. Use -j for JSON or -c <file.csv> to save raw results.")
    console.print(f"Cache path: {CACHE_PATH} (ttl {CACHE_TTL_HOURS}h)")

if __name__ == "__main__":
    main()
