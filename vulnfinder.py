#!/usr/bin/env python3
"""
vulnfinder.py - simple aggregator to find public vulnerabilities for a product+version.

Usage:
    python vulnfinder.py apache 1.8.5
    python vulnfinder.py "apache httpd" 2.4.54 --exploits --json
Notes:
    - Optional environment variable NVD_API_KEY can be set for higher NVD rate limits.
    - If 'searchsploit' is installed, use --exploits to include Exploit-DB matches.
"""

from __future__ import annotations
import argparse
import os
import json
import time
import shutil
import subprocess
import requests
import csv
from pathlib import Path
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table

# ---------------------------
# Config
# ---------------------------
OSV_API = "https://api.osv.dev/v1/query"
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PATH = Path.home() / ".vulnfinder_cache.json"
CACHE_TTL_HOURS = 12  # simple cache to avoid hammering APIs

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
        # expired
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
            out.append({
                "id": v.get("id"),
                "summary": v.get("summary") or (v.get("details") or "")[:400],
                "published": v.get("published"),
                "references": [ref.get("url") for ref in v.get("references", []) if ref.get("url")]
            })
        cache_set(key, out)
        return out
    except Exception:
        return []

# ---------------------------
# Helpers to find CPE strings
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
            r2 = requests.get(NVD_CPE_API, params={"keywordSearch": product, "resultsPerPage": 200}, headers=headers, timeout=20)
            if r2.ok:
                data2 = r2.json()
                for p in (data2.get("products") or []):
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
                    if not refs and isinstance(vuln.get("cve", {}).get("references"), list):
                        for rref in vuln.get("cve", {}).get("references", []):
                            if isinstance(rref, dict):
                                href = rref.get("url")
                                if href:
                                    refs.append(href)
                    if cve_id:
                        cves[cve_id] = {"id": cve_id, "description": desc, "references": refs}
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
        return None, "searchsploit not found on PATH"
    query = product + ((" " + version) if version else "")
    try:
        p = subprocess.run([prog, "--color", "never", query],
                           capture_output=True, text=True, timeout=20)
        out = p.stdout.strip()
        if not out:
            return [], ""
        return out.splitlines(), ""
    except Exception as e:
        return None, str(e)

# ---------------------------
# Printing / table helpers
# ---------------------------
def print_candidates_table(source_name: str, items):
    if not items:
        console.print(f"[{source_name}] No results found.")
        return
    table = Table(title=f"{source_name} Vulnerabilities", show_lines=True)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Description", style="white")
    table.add_column("References", style="magenta")
    for it in items:
        cid = it.get("id") or it.get("cve") or "?"
        desc = (it.get("summary") or it.get("description") or "").replace("\n"," ")[:300]
        refs = "\n".join(it.get("references", [])[:5])
        table.add_row(cid, desc, refs)
    console.print(table)

# ---------------------------
# CSV export
# ---------------------------
def export_csv(filename: str, results: dict):
    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Source", "CVE/ID", "Description", "References"])
            for source, items in results.get("sources", {}).items():
                if isinstance(items, list):
                    for it in items:
                        writer.writerow([source, it.get("id") or it.get("cve") or "?", 
                                         it.get("summary") or it.get("description") or "", 
                                         "; ".join(it.get("references", []))])
        console.print(f"[green]CSV saved to {filename}[/green]")
    except Exception as e:
        console.print(f"[red]Error saving CSV:[/red] {e}")

# ---------------------------
# CLI
# ---------------------------
def main():
    ap = argparse.ArgumentParser(description="VulnFinder: product and version specified separately")
    ap.add_argument("product", help="Product name (e.g., apache, openssh)")
    ap.add_argument("version", nargs="?", default=None, help="Product version (optional)")
    ap.add_argument("-e", "--exploits", action="store_true", help="Run local searchsploit")
    ap.add_argument("-j", "--json", action="store_true", help="Emit JSON")
    ap.add_argument("-c", "--csv", metavar="FILE", help="Export results to CSV")
    args = ap.parse_args()

    product = args.product.strip()
    version = args.version.strip() if args.version else None

    console.print(f"[bold]Searching vulnerabilities for:[/bold] product='{product}' version='{version or 'any'}' ...")

    results = {"query": {"product": product, "version": version}, 
               "timestamp": datetime.utcnow().isoformat(), "sources": {}}

    # OSV
    osv = query_osv(product, version)
    results["sources"]["osv"] = osv
    print_candidates_table("OSV", osv)

    # NVD
    nvd = search_nvd(product, version)
    results["sources"]["nvd"] = nvd
    print_candidates_table("NVD", nvd)

    # searchsploit
    if args.exploits:
        ss_out, ss_err = run_searchsploit(product, version)
        if ss_out is None:
            console.print(f"[red][searchsploit] error: {ss_err}[/red]")
            results["sources"]["searchsploit_error"] = ss_err
        else:
            results["sources"]["searchsploit"] = ss_out
            console.print("\n[searchsploit] raw results (first 20 lines):")
            for i, line in enumerate(ss_out):
                if i >= 20:
                    console.print("  ...")
                    break
                console.print(f"  {line}")

    # JSON output
    if args.json:
        print(json.dumps(results, indent=2))

    # CSV export
    if args.csv:
        export_csv(args.csv, results)

    console.print(f"\nDone. Use --json or --csv to save raw results.")
    console.print(f"Cache path: {CACHE_PATH} (ttl {CACHE_TTL_HOURS}h)")

if __name__ == "__main__":
    main()
