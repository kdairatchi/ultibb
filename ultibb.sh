#!/usr/bin/env bash
# Ultimate Bug Bounty Toolkit - Improved
# Author: <Your Name / AI Fusion>
# Purpose: Automate subdomain enumeration, URL gathering, port scanning, SSL checks,
#          fuzzing, vulnerability scanning, screenshot capture, and reporting.
# Usage:   ./ultibb.sh <target-domain>

set -euo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------
TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target-domain>"
    exit 1
fi

OUT_DIR="bb_scan_$(date +%s)"
REPORT_DIR="$OUT_DIR/report"
WORDLIST="${WORDLIST:-/home/anom/wordlists/oneListForall/onelistforallshort.txt}"  # or override with env var
THREADS="${THREADS:-20}"

# Tools required
REQUIRED_TOOLS=(
    nmap rustscan sslscan testssl.sh httpx nuclei katana gau
    ffuf subfinder amass gowitness htmlq jq parallel urlfinder wpscan assetfinder
    urldedupe subzy gf uro
)

# -----------------------------------------------------------
# 1) CHECK DEPENDENCIES
# -----------------------------------------------------------
check_deps() {
    echo "[+] Checking dependencies..."
    for dep in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            echo "[!] Missing dependency: $dep"
            exit 1
        fi
    done
    echo "[+] All dependencies found."
}

# -----------------------------------------------------------
# 2) SETUP DIRECTORIES
# -----------------------------------------------------------
setup_dirs() {
    echo "[+] Setting up directories in $OUT_DIR..."
    mkdir -p \
        "$OUT_DIR"/{subdomains,urls,ports,ssl,live_hosts,fuzz,nuclei,screenshots,httpx} \
        "$REPORT_DIR"/{data,assets}
    echo "[+] Directory structure created."
}

# -----------------------------------------------------------
# 3) SUBDOMAIN DISCOVERY
# -----------------------------------------------------------
subdomain_scan() {
    echo "[+] Starting subdomain enumeration for $TARGET"

    # subfinder
    subfinder -d "$TARGET" -silent \
        | tee "$OUT_DIR/subdomains/subfinder.txt"

    # amass (mix of active, passive)
    amass enum -d "$TARGET" -silent \
        | tee "$OUT_DIR/subdomains/amass.txt"
    amass enum -active -d "$TARGET" -silent \
        | tee -a "$OUT_DIR/subdomains/amass_active.txt"
    amass enum -passive -d "$TARGET" -silent \
        | tee -a "$OUT_DIR/subdomains/amass_passive.txt"

    # Combine all subdomains
    cat "$OUT_DIR/subdomains/"*.txt | sort -u > "$OUT_DIR/subdomains/final.txt"

    echo "[+] Subdomain enumeration complete. Unique subdomains saved to final.txt."
}

# -----------------------------------------------------------
# 4) SUBDOMAIN TAKEOVER CHECK
# -----------------------------------------------------------
subdomain_takeover_check() {
    echo "[+] Checking for possible subdomain takeovers..."
    # We'll rely on httpx to get subdomain:port combos for screening with subzy
    # Alternatively: subzy can take domain list directly
    subzy run \
        --targets "$OUT_DIR/subdomains/final.txt" \
        --concurrency 100 \
        --hide_fails \
        --verify_ssl \
        | tee "$OUT_DIR/subdomains/takeover.txt"

    echo "[+] Potential takeovers listed in takeover.txt (if any)."
}

# -----------------------------------------------------------
# 5) HTTPX / Live Hosts
# -----------------------------------------------------------
httpx_scan() {
    echo "[+] Probing subdomains with httpx to find live hosts..."

    # A comprehensive httpx run with JSON output for further analysis
    # - Make sure to quote expansions with double quotes for safety
    httpx \
        -l "$OUT_DIR/subdomains/final.txt" \
        -ss -srd "$OUT_DIR/screenshots" \
        -tech-detect -title -status-code -content-length -web-server \
        -ip -cname -cdn -location -jarm -favicon -hash sha256 -extraction-fqdn \
        -probe -silent \
        -json -o "$OUT_DIR/httpx/httpx_all.json"

    # Also produce a simpler text file of live endpoints
    httpx \
        -l "$OUT_DIR/subdomains/final.txt" \
        -title -status-code -ip -cname -probe -silent \
        | sort -u > "$OUT_DIR/httpx/live_raw.txt"

    # Extract 200 and 403 lines
    grep -E " 200 |^200 " "$OUT_DIR/httpx/live_raw.txt" || true > "$OUT_DIR/httpx/200_live.txt"
    grep -E " 403 |^403 " "$OUT_DIR/httpx/live_raw.txt" || true > "$OUT_DIR/httpx/403_live.txt"

    # Clean them to only keep the domain
    awk '{print $1}' "$OUT_DIR/httpx/200_live.txt" > "$OUT_DIR/httpx/clean_200_live.txt" || true
    awk '{print $1}' "$OUT_DIR/httpx/403_live.txt" > "$OUT_DIR/httpx/clean_403_live.txt" || true

    # Single file for "live hosts" usage
    grep -Eo '^https?://[^ ]+' "$OUT_DIR/httpx/live_raw.txt" | sort -u > "$OUT_DIR/live_hosts/live.txt"

    echo "[+] httpx completed. Results in httpx_all.json and live.txt."
}

# -----------------------------------------------------------
# 6) URL COLLECTION
# -----------------------------------------------------------
gather_urls() {
    echo "[+] Collecting URLs from subdomains..."

    # 1) Katana
    katana -silent -jc -d 5 -list "$OUT_DIR/subdomains/final.txt" \
        | tee "$OUT_DIR/urls/katana.txt"
    # second pass with extended flags
    katana -d 5 -silent -waybackarchive -commoncrawl -alienvault -kf -jc -fx -list "$OUT_DIR/subdomains/final.txt" \
        | tee "$OUT_DIR/urls/katana2.txt"

    # 2) urlfinder
    cat "$OUT_DIR/subdomains/final.txt" \
        | urlfinder --all \
        | sort -u > "$OUT_DIR/urls/urlfinder.txt"

    # 3) assetfinder (though typically for subdomains, can glean endpoints)
    cat "$OUT_DIR/subdomains/final.txt" \
        | assetfinder --subs-only \
        | sort -u > "$OUT_DIR/urls/assetfinder.txt"

    # 4) gau
    cat "$OUT_DIR/subdomains/final.txt" \
        | gau --subs \
        | sort -u > "$OUT_DIR/urls/gau.txt"

    # 5) waybackurls
    cat "$OUT_DIR/subdomains/final.txt" \
        | waybackurls \
        | sort -u > "$OUT_DIR/urls/wayback.txt"

    # Combine everything
    cat "$OUT_DIR/urls/"*.txt \
        | sort -u \
        | urldedupe \
        > "$OUT_DIR/urls/combined_urls.txt"

    echo "[+] URLs gathered in combined_urls.txt."

    # Potential GF patterns
    cat "$OUT_DIR/urls/combined_urls.txt" | gf xss    > "$OUT_DIR/urls/xss.txt"    || true
    cat "$OUT_DIR/urls/combined_urls.txt" | gf lfi    > "$OUT_DIR/urls/lfi.txt"    || true
    cat "$OUT_DIR/urls/combined_urls.txt" | gf redirect > "$OUT_DIR/urls/redirect.txt" || true
    cat "$OUT_DIR/urls/combined_urls.txt" | gf sqli   > "$OUT_DIR/urls/sqli.txt"   || true
    echo "[+] Stored potential GF matches: xss.txt, lfi.txt, sqli.txt, redirect.txt."
}

# -----------------------------------------------------------
# 7) LIVE HOST VERIFICATION (Alternative approach)
# -----------------------------------------------------------
verify_live_hosts() {
    echo "[+] (Optional) Additional verifying of combined URLs..."
    # Example: httpx on combined URLs
    httpx -l "$OUT_DIR/urls/combined_urls.txt" -status-code -title -tech-detect -json \
        -o "$OUT_DIR/live_hosts/urls_httpx.json" -silent
    echo "[+] Extra verification done."
}

# -----------------------------------------------------------
# 8) PORT SCANNING
# -----------------------------------------------------------
port_scan() {
    echo "[+] Starting port scans on subdomains..."

    # rustscan example (masscan-like)
    parallel -j 4 \
        "rustscan -a {} -g -u 5000 --timeout 1500 -- -Pn -sV -oN $OUT_DIR/ports/rustscan_{}.txt" \
        < "$OUT_DIR/subdomains/final.txt"

    # nmap
    parallel -j 2 \
        "nmap -p- -T4 --min-rate 1000 -oA $OUT_DIR/ports/nmap_{/} {}" \
        < "$OUT_DIR/subdomains/final.txt"

    # nmap scripts for ssl-cert if port 443 open, etc. (example)
    # ...
}

# -----------------------------------------------------------
# 9) SSL Checks
# -----------------------------------------------------------
ssl_checks() {
    echo "[+] Running SSL checks on subdomains with :443..."
    grep ':443$' "$OUT_DIR/subdomains/final.txt" | \
    parallel -j 4 "testssl --quiet --color 0 {} > $OUT_DIR/ssl/testssl_{/}.txt" || true

    grep ':443$' "$OUT_DIR/subdomains/final.txt" | \
    parallel -j 4 "sslscan {} > $OUT_DIR/ssl/sslscan_{/}.txt" || true

    echo "[+] SSL checks done."
}

# -----------------------------------------------------------
# 10) FUZZING
# -----------------------------------------------------------
run_fuzzing() {
    echo "[+] Starting fuzzing with ffuf..."

    # You might want to loop over each domain or subdomain, specifying FUZZ, etc.
    # Example: If you want to fuzz each domain with the wordlist, can use parallel.

    # Single example:
    ffuf \
        -w "$WORDLIST" \
        -u "FUZZ" \
        -t "$THREADS" \
        -ac \
        -fc 400,401,402,403,404,429,500,501,502,503 \
        -recursion -recursion-depth 2 \
        -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
        -H "X-Forwarded-For: 127.0.0.1" \
        -H "X-Originating-IP: 127.0.0.1" \
        -H "X-Forwarded-Host: localhost" \
        -of json -o "$OUT_DIR/fuzz/ffuf.json" \
        -ic

    jq -r '.results[].url' "$OUT_DIR/fuzz/ffuf.json" > "$OUT_DIR/fuzz/valid.txt" || true
    echo "[+] Fuzz results saved to $OUT_DIR/fuzz/ffuf.json."
}

# -----------------------------------------------------------
# 11) Nuclei Scanning
# -----------------------------------------------------------
run_nuclei() {
    echo "[+] Running Nuclei scans on $OUT_DIR/live_hosts/live.txt..."
    nuclei \
        -l "$OUT_DIR/live_hosts/live.txt" \
        -t ~/nuclei-templates/ \
        -severity critical,high,medium \
        -o "$OUT_DIR/nuclei/results.txt"

    echo "[+] Nuclei results in results.txt."
}

# -----------------------------------------------------------
# 12) Screenshots (Gowitness)
# -----------------------------------------------------------
capture_screenshots() {
    echo "[+] Capturing screenshots with gowitness..."
    gowitness file \
        -f "$OUT_DIR/live_hosts/live.txt" \
        -P "$OUT_DIR/screenshots" \
        --disable-logging

    echo "[+] Screenshots saved to $OUT_DIR/screenshots."
}

# -----------------------------------------------------------
# 13) REPORT GENERATION
# -----------------------------------------------------------
generate_report() {
    echo "[+] Generating HTML report..."

    # Example: convert httpx JSON to CSV with jq
    if [[ -f "$OUT_DIR/httpx/httpx_all.json" ]]; then
        jq -r '
          [
            .host,
            .port,
            .status_code,
            .title // "",
            .webserver // "",
            (.tech // []) | join("|")
          ] | @csv
        ' "$OUT_DIR/httpx/httpx_all.json" > "$REPORT_DIR/data/scan_results.csv" || true
    fi

    cat <<EOF > "$REPORT_DIR/index.html"
<html>
<head>
    <title>Ultimate Bug Bounty Report - $TARGET</title>
    <style>
      table { border-collapse: collapse; width: 100%; }
      th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
      tr:nth-child(even) { background-color: #f2f2f2; }
      img { max-width: 300px; height: auto; }
    </style>
</head>
<body>
  <h1>Bug Bounty Report: $TARGET</h1>
  <p>Generated: $(date)</p>

  <h2>Summary</h2>
  <ul>
    <li>Total Subdomains: $(wc -l < "$OUT_DIR/subdomains/final.txt" || echo 0)</li>
    <li>Live Hosts: $(wc -l < "$OUT_DIR/live_hosts/live.txt" || echo 0)</li>
    <li>Nuclei Findings: $(wc -l < "$OUT_DIR/nuclei/results.txt" || echo 0)</li>
  </ul>

  <h2>Scan Results</h2>
  <div id="table"></div>

  <script>
    async function loadData() {
      const response = await fetch('data/scan_results.csv');
      if (!response.ok) {
        document.getElementById('table').innerHTML = '<p>No HTTPX data found.</p>';
        return;
      }
      const text = await response.text();
      let lines = text.trim().split("\\n");
      let html = '<table><tr><th>Host</th><th>Port</th><th>Status</th><th>Title</th><th>Server</th><th>Tech</th></tr>';
      for (let i=0; i<lines.length; i++) {
        let cols = lines[i].split(",");
        html += \`<tr><td>\${cols[0]}</td><td>\${cols[1]}</td><td>\${cols[2]}</td><td>\${cols[3]}</td><td>\${cols[4]}</td><td>\${cols[5]}</td></tr>\`;
      }
      html += '</table>';
      document.getElementById('table').innerHTML = html;
    }
    loadData();
  </script>
</body>
</html>
EOF

    echo "[+] Report generated at $REPORT_DIR/index.html"
}

# -----------------------------------------------------------
# MAIN SEQUENCE
# -----------------------------------------------------------
main() {
    check_deps
    setup_dirs

    subdomain_scan
    subdomain_takeover_check
    httpx_scan
    gather_urls
    # verify_live_hosts  # optional extra step
    port_scan
    ssl_checks
    run_fuzzing
    run_nuclei
    capture_screenshots

    generate_report
    echo "[+] All tasks complete. See $REPORT_DIR for final report."
}

main
