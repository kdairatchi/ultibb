
# Ultimate Bug Bounty Toolkit

Automate reconnaissance and vulnerability scanning for bug bounty programs. This toolkit simplifies subdomain discovery, URL gathering, port scanning, SSL checks, fuzzing, vulnerability scanning (with Nuclei), screenshot capture, and report generation.

## Features

- **Subdomain Enumeration**: Combines multiple sources (Subfinder, Amass).
- **HTTP Probing**: Uses [httpx](https://github.com/projectdiscovery/httpx) to find live endpoints and detect tech stack.
- **URL Gathering**: Gathers endpoints via Katana, Gau, Waybackurls, URLFinder, and more.
- **Port Scanning**: Parallel usage of [rustscan](https://github.com/RustScan/RustScan) & [nmap](https://nmap.org/).
- **SSL Checks**: Automated checks with `sslscan`, `testssl.sh`.
- **Fuzzing**: High-speed fuzzing with [ffuf](https://github.com/ffuf/ffuf) using a configurable wordlist.
- **Vulnerability Scanning**: Integrates [Nuclei](https://github.com/projectdiscovery/nuclei) for fast detection of known flaws.
- **Subdomain Takeover**: Quick checks for takeover possibilities (via `subzy`).
- **Screenshots**: Captures screenshots of all live hosts (via Gowitness).
- **Report Generation**: Creates an HTML report with dynamic tables and stats.

## Requirements / Dependencies

Make sure the following tools are installed and accessible in your `$PATH`:

1. **Subdomain & URL**: 
   - [subfinder](https://github.com/projectdiscovery/subfinder), 
   - [amass](https://github.com/owasp-amass/amass), 
   - [assetfinder](https://github.com/tomnomnom/assetfinder), 
   - [katana](https://github.com/projectdiscovery/katana), 
   - [gau](https://github.com/lc/gau), 
   - [waybackurls](https://github.com/tomnomnom/waybackurls), 
   - [urlfinder](https://github.com/KingOfBugbounty/UrlFinder), 
   - [urldedupe](https://github.com/UnaPibaGeek/urldedupe)
2. **HTTP Probing**: [httpx](https://github.com/projectdiscovery/httpx)
3. **Port scanning**: [rustscan](https://github.com/RustScan/RustScan), [nmap](https://nmap.org/)
4. **SSL checks**: [sslscan](https://github.com/rbsec/sslscan), [testssl.sh](https://github.com/drwetter/testssl.sh)
5. **Fuzzing**: [ffuf](https://github.com/ffuf/ffuf)
6. **Vulnerability**: [nuclei](https://github.com/projectdiscovery/nuclei), [wpscan](https://github.com/wpscanteam/wpscan)
7. **Misc**: [gowitness](https://github.com/sensepost/gowitness), [htmlq](https://github.com/mgdm/htmlq), [jq](https://stedolan.github.io/jq), [parallel](https://www.gnu.org/software/parallel/), [gf](https://github.com/tomnomnom/gf), [uro](https://github.com/s0md3v/uro), [subzy](https://github.com/LukaSikic/subzy)

> On Debian-based systems, you might also need coreutils, unzip, etc. Install or compile from source as necessary.

## Installation

1. **Clone** the repository:
   ```bash
   git clone https://github.com/kdairatchi/ultibb.git
   cd Ultimate-Bug-Bounty-Toolkit
   ```
2. **Make the script executable**:
   ```bash
   chmod +x ultibb.sh
   ```
3. **Check** you have all required tools in `$PATH`.

## Usage

```bash
./ultibb.sh <target-domain>
```
Examples:
```bash
./ultibb.sh example.com
./ultibb.sh subdomain.example.org
```

### Flags & Environment Variables

- **`WORDLIST`**: Path to your fuzzing wordlist. Defaults to `/xxxx/wordlists/oneListForall/onelistforallshort.txt` if unset.
- **`THREADS`**: Concurrency for fuzzing. Defaults to 20.  
  ```bash
  THREADS=40 ./ultibb.sh example.com
  ```

After running, you’ll find a directory named `bb_scan_<timestamp>` containing subfolders for subdomains, URLs, ports, SSL scans, etc., as well as a `report/index.html` for an overview of findings.

## Workflow Overview

1. **Check Dependencies**  
   The script verifies that each required tool is installed.
2. **Subdomain Enumeration**  
   Gathers subdomains via `subfinder`, `amass`, merges them, and stores in `final.txt`.
3. **Subdomain Takeover Check**  
   Uses `subzy` to detect potential domain takeover vulnerabilities.
4. **HTTP Probing**  
   Uses `httpx` to identify live hosts, gather technology data, and produce JSON output.
5. **URL Gathering**  
   Aggregates endpoints from multiple sources (`katana`, `gau`, `waybackurls`, etc.).
6. **Port Scanning**  
   Runs `rustscan` and `nmap` in parallel.
7. **SSL Checks**  
   Runs `sslscan` & `testssl.sh` on hosts with port 443.
8. **Fuzzing**  
   Launches `ffuf` with a specified wordlist to discover hidden files/directories.
9. **Vulnerability Scanning**  
   Uses `nuclei` for template-based checks on discovered endpoints.
10. **Screenshots**  
   Captures site screenshots with `gowitness`.
11. **Report**  
   Generates an HTML file with aggregated info and a dynamic table fed by CSV/JSON.

## Example Output Structure

```
bb_scan_xxxx/
├── subdomains/
│   ├── subfinder.txt
│   ├── amass.txt
│   └── final.txt
├── urls/
│   ├── katana.txt
│   ├── gau.txt
│   └── combined_urls.txt
├── ports/
├── ssl/
├── live_hosts/
│   └── live.txt
├── fuzz/
├── nuclei/
│   └── results.txt
├── screenshots/
└── report/
    ├── data/
    │   └── scan_results.csv
    └── index.html
```

## Contributing

1. **Fork** the repo & create a new branch.
2. **Enhance** subdomain detection, add new tools, or fix bugs.
3. **Open a Pull Request** describing your changes.

## License

[MIT License](LICENSE) – feel free to modify and distribute under these terms.

## Disclaimer

This script automates scanning of public-facing assets for **bug bounty** or authorized pentests. Only use it against targets you **have permission** to test. The author is **not responsible** for any unauthorized use.

---

**Happy Bug Hunting!** For questions or suggestions, open an issue or submit a pull request.
