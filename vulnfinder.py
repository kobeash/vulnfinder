#!/usr/bin/env python3
"""
vulnfinder.py - simple aggregator to find public vulnerabilities for a product+version.
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

# ---------------------------
# Simple JSON cache
# ---------------------------
def load_cache() -> dict:
    if not CACHE_PATH.exists():
        return {}
    try:
        with open(CACHE_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def save_cache(cache: dict):
    try:
        with open(CACHE_PATH, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass

def cache_get(key: str):
    cache = load_cache()
    entry = cache.get(key)
    if not entry:
        return None
    ts = datetime.fromisoformat(entry.get('_ts'))
    if datetime.now(timezone.utc) - ts.replace(tzinfo=timezone.utc) > timedelta(hours=CACHE_TTL_HOURS):
        cache.pop(key, None)
        save_cache(cache)
        return None
    return entry.get('value')

def cache_set(key: str, value):
    cache = load_cache()
    cache[key] = {'_ts': datetime.now(timezone.utc).isoformat(), 'value': value}
    save_cache(cache)

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
def search_nvd(product: str, version: str | None):
    key = f'nvd:{product}:{version or ''}'
    cached = cache_get(key)
    if cached is not None:
        return cached

    apikey = os.getenv('NVD_API_KEY')
    headers = {'apiKey': apikey} if apikey else {}

    query = f'{product} {version}' if version else product
    params = {'keywordSearch': query, 'resultsPerPage': 200}
    try:
        r = requests.get(NVD_CPE_API, params=params, headers=headers, timeout=20)
        r.raise_for_status()
        data = r.json()
        products = data.get('products') or []
        cpe_candidates = set()
        for p in products:
            cpe_candidates |= find_cpe_strings(p)

        cves = {}
        for cpe in sorted(cpe_candidates):
            params_cve = {'cpeName': cpe, 'resultsPerPage': 2000}
            rcv = requests.get(NVD_CVE_API, params=params_cve, headers=headers, timeout=20)
            if rcv.ok:
                j = rcv.json()
                for vuln in j.get('vulnerabilities', []):
                    cve_obj = vuln.get('cve', {})
                    cve_id = cve_obj.get('id') or cve_obj.get('CVE_data_meta', {}).get('ID') or vuln.get('cveId')
                    desc = ''
                    for d in cve_obj.get('descriptions', []) if isinstance(cve_obj.get('descriptions'), list) else []:
                        if d.get('lang') == 'en':
                            desc = d.get('value') or ''
                            break
                    refs = [rref.get('url') for rref in cve_obj.get('references', []) if isinstance(rref, dict) and rref.get('url')]
                    if cve_id:
                        cves[cve_id] = {'id': cve_id, 'description': desc, 'references': refs}
            time.sleep(0.15)
        out = list(cves.values())
        cache_set(key, out)
        return out
    except Exception:
        return []

# ---------------------------
# searchsploit integration
# ---------------------------
def run_searchsploit(product: str, version: str | None):
    prog = shutil.which('searchsploit')
    if not prog:
        return None, 'searchsploit not found on PATH'
    query = f'{product} {version or ''}'.strip()
    try:
        p = subprocess.run([prog, '--color', 'never', query], capture_output=True, text=True, timeout=20)
        out = p.stdout.strip()
        return out.splitlines(), '' if out else []
    except Exception as e:
        return None, str(e)

# ---------------------------
# Variant-aware queries
# ---------------------------
def query_osv_variants(product: str, version: str | None):
    variants = [product] + product.split()[:2]
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
    return all_results

def search_nvd_variants(product: str, version: str | None):
    variants = [product] + product.split()[:2]
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
    return all_results

# ---------------------------
# CLI Printing helpers
# ---------------------------
def print_candidates(source_name: str, items, json_mode=False):
    if json_mode:
        return
    if not items:
        print(f'[{source_name}] No results found.')
        return
    print(f'\n[{source_name}] Found {len(items)} result(s):')
    for it in items:
        cid = it.get('id')
        desc = it.get('summary') or it.get('description') or (it.get('details') or '')[:300]
        print(f' - {cid or '?'}: {desc[:200].replace('\n',' ')}')
        refs = it.get('references') or []
        if refs:
            print('    refs:', ', '.join(refs[:3]))

# ---------------------------
# CSV Export
# ---------------------------
def save_to_csv(filename, results):
    rows = []
    for source, items in results.get('sources', {}).items():
        if isinstance(items, list):
            for it in items:
                rows.append({'source': source, 'id': it.get('id'), 'description': it.get('summary') or it.get('description'), 'references': ', '.join(it.get('references', []))})
    if rows:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['source','id','description','references'])
            writer.writeheader()
            writer.writerows(rows)
        print(f'CSV saved to {filename}')

# ---------------------------
# CLI
# ---------------------------
def main():
    ap = argparse.ArgumentParser(description='Simple vulnerability aggregator (OSV + NVD + local searchsploit)')
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
