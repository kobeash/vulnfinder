#!/usr/bin/env python3
"""
vulnfinder.py - enhanced vulnerability aggregator for arbitrary products and versions.
"""

from __future__ import annotations
import argparse
import os
import json
import time
import shutil
import subprocess
import requests
from urllib.parse import quote_plus
from pathlib import Path
from datetime import datetime, timezone, timedelta
import re
import csv

# ---------------------------
# Config
# ---------------------------
OSV_API = "https://api.osv.dev/v1/query"
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PATH = Path.home() / ".vulnfinder_cache.json"
CACHE_TTL_HOURS = 12
COMMON_SKIP = {'server', 'httpd', 'app', 'service'}

# ---------------------------
# Helpers
# ---------------------------
def extract_product_version(user_input: str):
    m = re.search(r"\bv?\d+(\.\d+)+\b", user_input)
    if m:
        version = m.group()
        product = user_input.replace(version, '').strip()
        return product, version
    return user_input.strip(), None

def normalize_product(name: str) -> str:
    return ' '.join(name.lower().strip().split())

def generate_variants(product: str):
    words = [w for w in product.split() if w not in COMMON_SKIP]
    variants = [' '.join(words)] + words
    return list(dict.fromkeys(variants))

# ---------------------------
# Simple JSON cache
# ---------------------------
# ... cache_get, cache_set, load_cache, save_cache remain unchanged (with timezone-aware datetime) ...

# ---------------------------
# OSV query
# ---------------------------
def query_osv(product: str, version: str | None):
    key = f'osv:{product}:{version or ''}'
    cached = cache_get(key)
    if cached is not None:
        return cached

    purl = f'pkg:generic/{product.lower().replace(' ', '_')}'
    payload = {'package': {'purl': purl}}
    if version:
        payload['version'] = version

    try:
        r = requests.post(OSV_API, json=payload, timeout=15)
        r.raise_for_status()
        data = r.json()
        vulns = data.get('vulns', []) or []
        out = []
        for v in vulns:
            out.append({
                'id': v.get('id'),
                'summary': v.get('summary') or (v.get('details') or '')[:400],
                'published': v.get('published'),
                'references': [ref.get('url') for ref in v.get('references', []) if ref.get('url')]
            })
        cache_set(key, out)
        return out
    except Exception:
        return []

# ---------------------------
# NVD query
# ---------------------------
# ... search_nvd remains unchanged ...

# ---------------------------
# Variant-aware queries with fallback
# ---------------------------
def query_osv_variants(product: str, version: str | None):
    variants = generate_variants(product)
    all_results = []
    seen_ids = set()
    for v in variants:
        res = query_osv(v, version)
        for r in res:
            if r['id'] not in seen_ids:
                all_results.append(r)
                seen_ids.add(r['id'])
        if all_results:
            break
    # fallback without version
    if not all_results and version:
        for v in variants:
            res = query_osv(v, None)
            for r in res:
                if r['id'] not in seen_ids:
                    all_results.append(r)
                    seen_ids.add(r['id'])
            if all_results:
                break
    return all_results

def search_nvd_variants(product: str, version: str | None):
    variants = generate_variants(product)
    all_results = []
    seen_ids = set()
    for v in variants:
        res = search_nvd(v, version)
        for r in res:
            if r['id'] not in seen_ids:
                all_results.append(r)
                seen_ids.add(r['id'])
        if all_results:
            break
    if not all_results and version:
        for v in variants:
            res = search_nvd(v, None)
            for r in res:
                if r['id'] not in seen_ids:
                    all_results.append(r)
                    seen_ids.add(r['id'])
            if all_results:
                break
    return all_results

# ---------------------------
# CLI Printing helpers
# ---------------------------
# ... print_candidates remains unchanged ...

# ---------------------------
# CSV Export
# ---------------------------
# ... save_to_csv remains unchanged ...

# ---------------------------
# searchsploit integration
# ---------------------------
# ... run_searchsploit remains unchanged ...

# ---------------------------
# CLI
# ---------------------------
def main():
    ap = argparse.ArgumentParser(description='VulnFinder: vulnerability aggregator')
    ap.add_argument('product', help='product name and optional version (e.g. "apache httpd 2.4.54")')
    ap.add_argument('-e', '--exploits', action='store_true', help='also run local searchsploit (if installed)')
    ap.add_argument('-j', '--json', action='store_true', help='emit JSON instead of pretty text')
    ap.add_argument('-c', '--csv', help='save results to CSV file')
    args = ap.parse_args()

    product_input = args.product
    product, version = extract_product_version(product_input)
    product = normalize_product(product)

    print(f"Searching vulnerabilities for: product='{product}' version='{version or 'any'}' ...")

    results = {'query': {'product': product, 'version': version}, 'timestamp': datetime.now(timezone.utc).isoformat(), 'sources': {}}

    osv = query_osv_variants(product, version)
    results['sources']['osv'] = osv
    print_candidates('OSV', osv, json_mode=args.json)

    nvd = search_nvd_variants(product, version)
    results['sources']['nvd'] = nvd
    print_candidates('NVD', nvd, json_mode=args.json)

    if args.exploits:
        ss_out, ss_err = run_searchsploit(product, version)
        if ss_out is None:
            print('\n[searchsploit] error:', ss_err)
            results['sources']['searchsploit_error'] = ss_err
        else:
            results['sources']['searchsploit'] = ss_out

    if args.json:
        print(json.dumps(results, indent=2))

    if args.csv:
        save_to_csv(args.csv, results)

    if not args.json:
        print('\nDone. Use --json or --csv to save raw results.')
        print(f'Cache path: {CACHE_PATH} (ttl {CACHE_TTL_HOURS}h)')

if __name__ == '__main__':
    main()
