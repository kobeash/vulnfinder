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

    purl = f"pkg:generic/{product.replace(' ', '_')}"
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
# Helpers to find strings in nested structures
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
# NVD CPE -> CVE flow
# ---------------------------
# (same as before, unchanged)

# ---------------------------
# searchsploit integration
# ---------------------------
# (same as before, unchanged)

# ---------------------------
# Printing helpers with improved CLI readability
# ---------------------------
def print_candidates(source_name: str, items, json_mode=False):
    if json_mode:
        return
    if not items:
        print(f"[{source_name}] No results found.\n")
        return

    print(f"\n=== [{source_name}] Found {len(items)} result(s) ===")
    for idx, it in enumerate(items, 1):
        cid = it.get("id") or it.get("cve") or it.get("CVE") or "?"
        desc = it.get("summary") or it.get("description") or (it.get("details") or "")
        refs = it.get("references") or []

        print(f"\n[{idx}] {cid}")
        print(f"Description: {desc[:500].replace(chr(10), ' ')}")
        if refs:
            print("References:")
            for r in refs[:5]:
                print(f"  - {r}")
        print("-" * 60)

# Improved searchsploit output formatting
def print_searchsploit(ss_lines):
    if not ss_lines:
        print("[searchsploit] No exploits found.")
        return

    print("\n=== [searchsploit] Top results ===")
    for idx, line in enumerate(ss_lines[:20], 1):
        print(f"[{idx}] {line}")
    if len(ss_lines) > 20:
        print(f"  ...and {len(ss_lines)-20} more results")

# ---------------------------
# CSV Export
# ---------------------------
# (same as before, unchanged)

# ---------------------------
# CLI
# ---------------------------
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
