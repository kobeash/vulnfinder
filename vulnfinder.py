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
        product = user_input.replace(version, "").strip()
        return product, version
    return user_input.strip(), None

def normalize_product(name: str) -> str:
    return " ".join(name.lower().strip().split())

# ---------------------------
# Simple JSON cache
# ---------------------------
# (same as before)

# ---------------------------
# OSV query
# ---------------------------
# (same as before)

# ---------------------------
# Helpers to find strings in nested structures
# ---------------------------
# (same as before)

# ---------------------------
# NVD CPE -> CVE flow
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

        cves = {}
        for cpe in sorted(cpe_candidates):
            params_cve = {"cpeName": cpe, "resultsPerPage": 2000}
            rcv = requests.get(NVD_CVE_API, params=params_cve, headers=headers, timeout=20)
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
                refs = []
                for rref in cve_obj.get("references", []):
                    href = rref.get("url") or rref.get("reference_data", {}).get("url")
                    if href:
                        refs.append(href)
                if cve_id:
                    cves[cve_id] = {"id": cve_id, "description": desc, "references": refs}
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
    prog = shutil.which("searchsploit")
    if not prog:
        return None, "searchsploit not found on PATH"
    query = product + (" " + version if version else "")
    try:
        p = subprocess.run([prog, "--color", "never", query], capture_output=True, text=True, timeout=20)
        out = p.stdout.strip()
        return out.splitlines(), "" if out else ([], "")
    except Exception as e:
        return None, str(e)

# ---------------------------
# Printing helpers with improved CLI readability
# ---------------------------
# (same as before)

# ---------------------------
# CSV Export
# ---------------------------
def save_to_csv(filename: str, results: dict):
    try:
        with open(filename, "w", newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Source", "ID", "Description", "References"])
            for source, items in results.get("sources", {}).items():
                if isinstance(items, list):
                    for it in items:
                        writer.writerow([source, it.get("id") or it.get("cve") or "?", it.get("summary") or it.get("description") or "", ", ".join(it.get("references") or [])])
    except Exception as e:
        print(f"Error saving CSV: {e}")

# ---------------------------
# CLI
# ---------------------------
# (same as before, unchanged)

def main():
    ap = argparse.ArgumentParser(description="Simple vulnerability aggregator (OSV + NVD + local searchsploit)")
    ap.add_argument("product", help="product name (e.g. 'apache httpd 2.4.54' or 'MyApp 1.2.3')")
    ap.add_argument("-e", "--exploits", action="store_true", help="also run local searchsploit (if installed)")
    ap.add_argument("-j", "--json", action="store_true", help="emit JSON instead of pretty text")
    ap.add_argument("-c", "--csv", help="save results to CSV file")
    args = ap.parse_args()

    raw_input = args.product
    product, version = extract_product_version(raw_input)
    product = normalize_product(product)

    print(f"Searching vulnerabilities for: product='{product}' version='{version or 'any'}' ...")

    results = {
        "query": {"product": product, "version": version},
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sources": {}
    }

    osv = query_osv(product, version)
    results["sources"]["osv"] = osv
    print_candidates("OSV", osv, json_mode=args.json)

    nvd = search_nvd(product, version)
    results["sources"]["nvd"] = nvd
    print_candidates("NVD", nvd, json_mode=args.json)

    if args.exploits:
        ss_out, ss_err = run_searchsploit(product, version)
        if ss_out is None:
            print("\n[searchsploit] error:", ss_err)
            results["sources"]["searchsploit_error"] = ss_err
        else:
            results["sources"]["searchsploit"] = ss_out
            if not args.json:
                print_searchsploit(ss_out)

    if args.json:
        print(json.dumps(results, indent=2))

    if args.csv:
        save_to_csv(args.csv, results)

    if not args.json:
        print("\nDone. Save results to JSON with --json if you want to keep raw data.")
        print(f"Cache path: {CACHE_PATH} (ttl {CACHE_TTL_HOURS}h)")

if __name__ == "__main__":
    main()
