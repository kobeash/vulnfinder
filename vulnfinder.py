#!/usr/bin/env python3
"""
vulnfinder.py - simple vulnerability aggregator with separate product and version inputs.
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
from datetime import datetime, timezone, timedelta

# ---------------------------
# Config
# ---------------------------
OSV_API = "https://api.osv.dev/v1/query"
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PATH = Path.home() / ".vulnfinder_cache.json"
CACHE_TTL_HOURS = 12

# ---------------------------
# Simple JSON cache
# ---------------------------
# ... (cache_get, cache_set, load_cache, save_cache) remain unchanged ...

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
        out = [{'id': v.get('id'), 'summary': v.get('summary') or (v.get('details') or '')[:400],
                'published': v.get('published'),
                'references': [ref.get('url') for ref in v.get('references', []) if ref.get('url')]} for v in vulns]
        cache_set(key, out)
        return out
    except Exception:
        return []

# ---------------------------
# NVD query
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
        cves = []
        # Simplified extraction (keep previous logic for extracting CPE -> CVE)
        cache_set(key, cves)
        return cves
    except Exception:
        return []

# ---------------------------
# Printing / CLI helpers
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
        print(f" - {cid or '?'}: {desc[:200].replace('\n',' ')}")
        refs = it.get('references', [])
        if refs:
            print("    refs:", ', '.join(refs[:3]))

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
# CLI
# ---------------------------
def main():
    ap = argparse.ArgumentParser(description='VulnFinder: product and version specified separately')
    ap.add_argument('product', help='Product name (e.g., apache, openssh)')
    ap.add_argument('version', nargs='?', default=None, help='Product version (optional)')
    ap.add_argument('-e', '--exploits', action='store_true', help='run local searchsploit')
    ap.add_argument('-j', '--json', action='store_true', help='emit JSON')
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
            print('\n[searchsploit] error:', ss_err)
            results['sources']['searchsploit_error'] = ss_err
        else:
            results['sources']['searchsploit'] = ss_out
            for line in ss_out[:20]:
                print('  '+line)
            if len(ss_out) > 20:
                print('  ...')

    if args.json:
        import json
        print(json.dumps(results, indent=2))

    print('\nDone. Use --json to save raw results.')
    print(f'Cache path: {CACHE_PATH} (ttl {CACHE_TTL_HOURS}h)')

if __name__ == '__main__':
    main()
