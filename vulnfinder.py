#!/usr/bin/env python3
"""
vulnfinder.py - simple vulnerability aggregator

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
from pathlib import Path
from datetime import datetime, timedelta, timezone
import csv

# ---------------------------
# Config
# ---------------------------
OSV_API = "https://api.osv.dev/v1/query"
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PATH = Path.home() / ".vulnfinder_cache.json"
CACHE_TTL_HOURS = 12  # simple cache to avoid hammering APIs

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
    if datetime.now(timezone.utc) - ts.replace(tzinfo=timezone.utc) > timedelta(hours=CACHE_TTL_HOURS):
        # expired
        cache.pop(key, None)
        save_cache(cache)
        return None
    return entry.get("value")

def cache_set(key: str, value):
    cache = load_cache()
    cache[key] = {"_ts": datetime.now(timezone.utc).isoformat(), "value": value}
    save_cache(cache)

# ---------------------------
# OSV query
# ---------------------------
def query_osv(product: str, version: str | None):
    key = f"osv:{product}:{version or ''}"
    cached = cache_get(key)
    if cached is not None:
        return cached

    payload = {'package': {'name': product}}
    if version:
        payload['version'] = version

    try:
        r = requests.post(OSV_API, json=payload, timeout=15)
        r.raise_for_status()
        data = r.json()
        vulns = data.get('vulns', []) or []
        out = [{'id': v.get('id'),
                'summary': v.get('summary') or (v.get('details') or '')[:400],
                'published': v.get('published'),
                'references': [ref.get('url') for ref in v.get('references', []) if ref.get('url')]} for v in vulns]
        cache_set(key, out)
        return out
    except Exception:
        return []

# ---------------------------
# NVD query (simplified)
# ---------------------------
def search_nvd(product: str, version: str | None):
    key = f"nvd:{product}:{version or ''}"
    cached = cache_get(key)
    if cached is not None:
        return cached

    apikey = os.getenv('NVD_API_KEY')
    headers = {'apiKey': apikey} if apikey else {}
    query = f"{product} {version}" if version else product
    params = {'keywordSearch': query, 'resultsPerPage': 200}

    try:
        r = requests.get(NVD_CPE_API, params=params, headers=headers, timeout=20)
        r.raise_for_status()
        data = r.json()
        # simplified: not doing full CPE -> CVE resolution
        cves = []
        cache_set(key, cves)
        return cves
    except Exception:
        return []

# ---------------------------
# searchsploit
# ---------------------------
def run_searchsploit(product: str, version: str | None):
    prog = shutil.which('searchsploit')
    if not prog:
        return None, 'searchsploit not found on PATH'
    query = f"{product} {version}" if version else product
    try:
        p = subprocess.run([prog, '--color', 'never', query], capture_output=True, text=True, timeout=20)
        out = p.stdout.strip().splitlines() if p.stdout else []
        return out, ''
    except Exception as e:
        return None, str(e)

# ---------------------------
# CLI output
# ---------------------------
def print_candidates(source_name: str, items, json_mode=False):
    if json_mode:
        return
    if not items:
        print(f"[{source_name}] No results found.")
        return
    print(f"\n[{source_name}] {len(items)} result(s):")
    for it in items:
        cid = it.get('id')
        desc = it.get('summary', '')
        print(f" - {cid or '?'}: {desc[:200].replace('\\n',' ')}")
        refs = it.get('references', [])
        if refs:
            print("    refs:", ', '.join(refs[:3]))

# ---------------------------
# CSV export
# ---------------------------
def export_csv(results, path='vulnfinder_results.csv'):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['source','id','summary','published','references'])
        for source, items in results['sources'].items():
            if not isinstance(items, list):
                continue
            for it in items:
                writer.writerow([source, it.get('id'), it.get('summary'), it.get('published'), ';'.join(it.get('references', []))])
    print(f"Results exported to CSV: {path}")

# ---------------------------
# Main CLI
# ---------------------------
def main():
    ap = argparse.ArgumentParser(description="VulnFinder: product and version separately")
    ap.add_argument("product", help="Product name (e.g., apache, openssh)")
    ap.add_argument("version", nargs="?", default=None, help="Product version (optional)")
    ap.add_argument("-e", "--exploits", action="store_true", help="run local searchsploit")
    ap.add_argument("-j", "--json", action="store_true", help="emit JSON")
    ap.add_argument("--csv", action="store_true", help="export results to CSV")
    args = ap.parse_args()

    product = args.product.strip()
    version = args.version.strip() if args.version else None

    print(f"Searching vulnerabilities for: product='{product}' version='{version or 'any'}' ...")

    results = {'query': {'product': product, 'version': version}, 'timestamp': datetime.now(timezone.utc).isoformat(), 'sources': {}}

    osv = query_osv(product, version)
    results['sources']['osv'] = osv
    print_candidates('OSV', osv, json_mode=args.json)

    nvd = search_nvd(product, version)
    results['sources']['nvd'] = nvd
    print_candidates('NVD', nvd, json_mode=args.json)

    if args.exploits:
        ss_out, ss_err = run_searchsploit(product, version)
        if ss_out is None:
            print("\n[searchsploit] error:", ss_err)
            results['sources']['searchsploit_error'] = ss_err
        else:
            results['sources']['searchsploit'] = ss_out
            print("\n[searchsploit] raw results (first 20 lines):")
            for i, line in enumerate(ss_out[:20]):
                print("  " + line)
            if len(ss_out) > 20:
                print("  ...")

    if args.json:
        print(json.dumps(results, indent=2))

    if args.csv:
        export_csv(results)

    print("\nDone. Use --json or --csv to save raw results.")
    print(f"Cache path: {CACHE_PATH} (ttl {CACHE_TTL_HOURS}h)")

if __name__ == "__main__":
    main()
