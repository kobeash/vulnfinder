# VulnFinder

**VulnFinder** is a simple Python-based vulnerability aggregator that helps you find public vulnerabilities for a given product and version. It queries multiple sources including [OSV](https://osv.dev), [NVD](https://nvd.nist.gov), and optionally local Exploit-DB (via `searchsploit`).

---

## Features

- Query vulnerabilities by product name and optional version.
- Aggregates results from multiple sources:
  - **OSV** (Open Source Vulnerabilities)
  - **NVD** (National Vulnerability Database)
  - **Searchsploit** (local Exploit-DB, optional)
- Simple caching to avoid repeated API calls.
- Optional JSON output for further processing.
- Works with both exact and fuzzy product names.
- Handles API rate limits gracefully.

---

## Installation

1. Clone this repository:

```bash
git clone https://github.com/kobeash/vulnfinder
cd vulnfinder
```

2. Install dependencies locally into the `deps` folder:

```bash
pip install --upgrade --target=./deps -r requirements.txt
```

> Requirements:
> - `requests`
> - `rich` (optional, for nicer CLI output)
> - `typer`

3. (Optional) Install `searchsploit` if you want local Exploit-DB integration:

```bash
sudo apt install exploitdb   # Debian/Ubuntu
```

4. (Optional) Set your NVD API key for higher rate limits:

```bash
export NVD_API_KEY="your_api_key_here"
```

---

## Running the Tool

A helper script `run_vulnfinder.sh` is provided to automatically use the local dependencies:

```bash
./run_vulnfinder.sh <product> [version] [--exploits] [--json]
```

### Examples

- Search Apache vulnerabilities (any version):

```bash
./run_vulnfinder.sh apache
```

- Search a specific version of Apache HTTPD:

```bash
./run_vulnfinder.sh "apache httpd" 2.4.54
```

- Include local `searchsploit` results:

```bash
./run_vulnfinder.sh apache 1.8.5 --exploits
```

- Output results in JSON format:

```bash
./run_vulnfinder.sh "apache httpd" 2.4.54 --json
```

---

## Caching

- Cache is stored at `~/.vulnfinder_cache.json`.
- Default TTL is 12 hours to reduce repeated API calls.
- Can be safely deleted to force fresh queries.

---

## Sources

- **OSV**: Queries vulnerabilities using package URLs (`pkg:generic/...`) via [OSV API](https://api.osv.dev/).
- **NVD**: Uses CPE and CVE APIs to find vulnerabilities.
- **Searchsploit**: Queries local Exploit-DB installation for matching exploits.

---

## Notes

- The tool is read-only and does not exploit vulnerabilities.
- JSON output is suitable for automation or integration with other tools.
- CLI output is designed for quick human inspection.
- Dependencies are installed locally in `deps` to avoid system-wide installation.

---

## License

MIT License © Your Name

---

## Contribution

Contributions, suggestions, and improvements are welcome! Feel free to submit issues or pull requests.
