```markdown
# VulnFinder

**VulnFinder** is a simple Python-based vulnerability aggregator that helps you find public vulnerabilities for a given product and version. It queries multiple sources including [OSV](https://osv.dev), [NVD](https://nvd.nist.gov), and optionally local Exploit-DB (via `searchsploit`).

---

## Features

- Query vulnerabilities by **product name** and **optional version**.
- Aggregates results from multiple sources:
  - **OSV** (Open Source Vulnerabilities)
  - **NVD** (National Vulnerability Database)
  - **Searchsploit** (local Exploit-DB, optional, table-formatted output)
- Simple caching to avoid repeated API calls.
- Optional JSON or CSV output for automation.
- Works with both exact and fuzzy product names.
- Handles API rate limits gracefully.

---

## Installation

1. Clone this repository:

```bash
git clone https://github.com/kobeash/vulnfinder
cd vulnfinder
```

2. Install dependencies **locally in `deps` folder** (no system-wide install needed):

```bash
pip install --upgrade --target=./deps -r requirements.txt
```

> Requirements: `requests`, `rich` (for CLI tables)

3. (Optional) Install `searchsploit` if you want local Exploit-DB integration:

```bash
sudo apt install exploitdb   # Debian/Ubuntu
```

4. (Optional) Set your NVD API key for higher rate limits:

```bash
export NVD_API_KEY="your_api_key_here"
```

---

## Usage

Use the wrapper script `run_vulnfinder.sh`:

```bash
./run_vulnfinder.sh <product> <version> [options]
```

### Options

- `-e, --exploits` → Run local searchsploit  
- `-j, --json` → Output results in JSON  
- `--csv` → Export results to CSV  

### Examples

```bash
# Basic product + version
./run_vulnfinder.sh "Apache" "1.3.20"

# Product with space in name
./run_vulnfinder.sh "Apache httpd" "2.4.54"

# Include local searchsploit (table output)
./run_vulnfinder.sh "Apache" "1.3.20" -e

# JSON output
./run_vulnfinder.sh "Apache" "1.3.20" -j

# CSV export
./run_vulnfinder.sh "Apache" "1.3.20" --csv

# Combined
./run_vulnfinder.sh "Apache httpd" "2.4.54" -e -j --csv
```

---

## Caching

- Cache is stored at `~/.vulnfinder_cache.json`.
- Default TTL is 12 hours.
- Can be safely deleted to force fresh queries.

---

## Sources

- **OSV**: Queries vulnerabilities via package URLs (`pkg:generic/...`) using [OSV API](https://api.osv.dev/).  
- **NVD**: Uses CPE and CVE APIs to find vulnerabilities.  
- **Searchsploit**: Queries local Exploit-DB installation for matching exploits and displays in a **table format** for readability.

---

## Notes

- The tool is read-only and does **not exploit vulnerabilities**.  
- JSON/CSV output is suitable for automation or integration with other tools.  
- CLI output is designed for quick human inspection.
```
