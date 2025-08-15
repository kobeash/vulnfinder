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
from urllib.parse import quote_plus
from pathlib import Path
from datetime import datetime, timedelta

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

    # Try package purl generic first (works for many non-ecosystem products)
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
        # Non-fatal: return empty list on failure
        return []

# ---------------------------
# Helpers to find strings in nested structures
# ---------------------------
def find_cpe_strings(obj):
    """Recursively search for strings that look like CPE 2.3 URIs."""
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
def search_nvd(product: str, version: str | None):
    key = f"nvd:{product}:{version or ''}"
    cached = cache_get(key)
    if cached is not None:
        return cached

    apikey = os.getenv("NVD_API_KEY")
    headers = {}
    if apikey:
        # NVD expects an API key in a header named 'apiKey' (case-sensitive as docs say).
        headers["apiKey"] = apikey

    # Build keyword search. If version supplied, include it to find more precise CPEs.
    query = f"{product} {version}" if version else product
    params = {"keywordSearch": query, "resultsPerPage": 200}
    try:
        r = requests.get(NVD_CPE_API, params=params, headers=headers, timeout=20)
        r.raise_for_status()
        data = r.json()
        products = data.get("products") or []
        # Extract candidate CPE strings
        cpe_candidates = set()
        for p in products:
            # the API schema may put CPEs in different keys; search recursively
            cpe_candidates |= find_cpe_strings(p)
        if not cpe_candidates and version:
            # fallback: try without version
            params2 = {"keywordSearch": product, "resultsPerPage": 200}
            r2 = requests.get(NVD_CPE_API, params=params2, headers=headers, timeout=20)
            if r2.ok:
                data2 = r2.json()
                for p in (data2.get("products") or []):
                    cpe_candidates |= find_cpe_strings(p)

        cves = {}
        for cpe in sorted(cpe_candidates):
            # Query CVEs for each candidate CPE
            params = {"cpeName": cpe, "resultsPerPage": 2000}
            try:
                rcv = requests.get(NVD_CVE_API, params=params, headers=headers, timeout=20)
                if rcv.status_code != 200:
                    continue
                j = rcv.json()
                for vuln in j.get("vulnerabilities", []):
                    # robustness: try a few common fields for CVE ID and description
                    cve_obj = vuln.get("cve", {})
                    cve_id = cve_obj.get("id") or \
                             cve_obj.get("CVE_data_meta", {}).get("ID") or \
                             vuln.get("cveId")
                    # description:
                    desc = ""
                    # modern schema often has descriptions list:
                    for d in cve_obj.get("descriptions", []) if isinstance(cve_obj.get("descriptions"), list) else []:
                        if d.get("lang") == "en":
                            desc = d.get("value") or ""
                            break
                    if not desc:
                        # try other locations
                        desc = (cve_obj.get("descriptions") or "") if isinstance(cve_obj.get("descriptions"), str) else desc
                    # references maybe under 'references' or in top-level
                    refs = []
                    if isinstance(cve_obj.get("references"), list):
                        for rref in cve_obj.get("references"):
                            href = rref.get("url") or rref.get("reference_data", {}).get("url")
                            if href:
                                refs.append(href)
                    # fallback: top-level references
                    if not refs and isinstance(vuln.get("cve", {}).get("references"), list):
                        for rref in vuln.get("cve", {}).get("references", []):
                            if isinstance(rref, dict):
                                href = rref.get("url")
                                if href:
                                    refs.append(href)
                    if cve_id:
                        cves[cve_id] = {"id": cve_id, "description": desc, "references": refs}
                # polite small delay to be kind to the API
                time.sleep(0.15)
            except Exception:
                continue

        out = list(cves.values())
        cache_set(key, out)
        return out
    except Exception:
        return []

# ---------------------------
# searchsploit (local Exploit-DB) integration
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
        # return raw searchsploit output; parsing CLI table reliably is annoying across versions,
        # so we provide the output for human inspection.
        return out.splitlines(), ""
    except Exception as e:
        return None, str(e)

# ---------------------------
# Printing / output helpers
# ---------------------------
def print_candidates(source_name: str, items, json_mode=False):
    if json_mode:
        return
    if not items:
        print(f"[{source_name}] no results.")
        return
    print(f"\n[{source_name}] found {len(items)} result(s):")
    for it in items:
        # flexible keys
        cid = it.get("id") or it.get("cve") or it.get("CVE")
        desc = it.get("summary") or it.get("description") or (it.get("details") or "")[:300]
        print(f" - {cid or '?'}: {desc[:200].replace('\\n',' ')}")
        refs = it.get("references") or []
        if refs:
            print("    refs:", ", ".join(refs[:3]))

# ---------------------------
# CLI
# ---------------------------
def main():
    ap = argparse.ArgumentParser(description="Simple vulnerability aggregator (OSV + NVD + local searchsploit)")
    ap.add_argument("product", help="product name (e.g. apache, 'apache httpd', openssh')")
    ap.add_argument("version", nargs="?", default=None, help="optional version (e.g. 1.8.5)")
    ap.add_argument("--exploits", action="store_true", help="also run local searchsploit (if installed)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of pretty text")
    args = ap.parse_args()

    product = args.product.strip()
    version = args.version.strip() if args.version else None

    print(f"Searching vulnerabilities for: product='{product}' version='{version or 'any'}' ...")

    results = {"query": {"product": product, "version": version}, "timestamp": datetime.utcnow().isoformat(), "sources": {}}

    # OSV
    osv = query_osv(product, version)
    results["sources"]["osv"] = osv
    print_candidates("OSV", osv, json_mode=args.json)

    # NVD
    nvd = search_nvd(product, version)
    results["sources"]["nvd"] = nvd
    print_candidates("NVD", nvd, json_mode=args.json)

    # optional searchsploit
    if args.exploits:
        ss_out, ss_err = run_searchsploit(product, version)
        if ss_out is None:
            print("\n[searchsploit] error:", ss_err)
            results["sources"]["searchsploit_error"] = ss_err
        else:
            # keep raw output lines
            results["sources"]["searchsploit"] = ss_out
            if not args.json:
                print("\n[searchsploit] raw results (first 20 lines):")
                for i, line in enumerate(ss_out):
                    if i >= 20:
                        print("  ...")
                        break
                    print("  " + line)

    # final JSON output or summary
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("\nDone. Save results to JSON with --json if you want to keep raw data.")
        print(f"Cache path: {CACHE_PATH} (ttl {CACHE_TTL_HOURS}h)")

if __name__ == "__main__":
    main()
