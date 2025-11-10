import nmap
import ipaddress
import re
import sys
import requests
import time
import os
import colorama
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

#----COLOR-SETUP---------------------------------------------------------------------
try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init()
except Exception:
    # fallback minimal ANSI
    class _Fore:
        BLACK = '\033[30m';
        RED = '\033[31m';
        GREEN = '\033[32m';
        YELLOW = '\033[33m'
        BLUE = '\033[34m';
        MAGENTA = '\033[35m';
        CYAN = '\033[36m'
        WHITE = '\033[37m';
        RESET = '\033[39m'
    class _Style:
        BRIGHT = '\033[1m';  NORMAL = '\033[0m'; RESET_ALL = '\033[0m'
    Fore = _Fore()
    Style = _Style()

def color_for_severity(sev: str) -> str:
    s = (sev or "").upper()
    if s in ("CRITICAL", "HIGH"):
        return Fore.RED + Style.BRIGHT
    if s == "MEDIUM":
        return Fore.YELLOW + Style.BRIGHT
    if s in ("LOW", "N/A"):
        return Fore.GREEN + Style.BRIGHT
    return Fore.WHITE + Style.NORMAL



#------------------------------------------------------------------------------

NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
API_CALL_DELAY = 0.6


#not used yet
def compute_risk_score(severity, port, cve_count=1, version_known=False):
    sev = severity.upper()
    score = 0

    # Severity
    sev_weights = {"CRITICAL": 10, "HIGH": 8, "LOW": 2}
    score += sev_weights.get(sev, 0)

    # Port exposure
    high_risk_ports = [21, 22, 23, 25, 80, 443, 445, 3389]
    if port in high_risk_ports:
        score += 2

    # Version confidence
    if version_known:
        score += 1

    # More CVEs = slightly higher risk
    score += min(5, cve_count)

    return score


def getIpAddress():
    while True:
        ip_add_entered = input("\nPlease enter the ip address that you want to scan: ").strip()
        try:
            ip_address_obj = ipaddress.ip_address(ip_add_entered)
            print("You entered a valid ip address.")
            return str(ip_address_obj)
        except Exception:
            print("You entered an invalid ip address. Try again.")


def nmapsV(ip_address):
    nm = nmap.PortScanner()
    base_scan = '-sS' if os.geteuid() == 0 else '-sT' #-sS if root, else -sT
    args = f"{base_scan} -sV --open -T4 --min-rate 1000 --max-retries 1 --host-timeout 60s"
    print(f"\nRunning ( nmap {args} ) on {ip_address} ... (this may take a bit)")

    try:
         nm.scan(hosts=ip_address, arguments=args)
    except Exception as e:
        print(f"Error running nmap: {e}")
        sys.exit(1)

    if ip_address not in nm.all_hosts():
        return []

    # table output
    print("\nScan results:")
    hdr = f"{'PORT':>6}  {'STATE':>7}  {'SERVICE':<12}  {'PRODUCT':<20}  {'VERSION':<12}  {'EXTRA'}"
    print(Style.BRIGHT + hdr + Style.RESET_ALL)
    print("-" * 90)

    open_services = []
    tcp = nm[ip_address].get('tcp', {})
    for port, info in sorted(tcp.items()):
        if info.get('state') == 'open':
            state = info.get('state', 'unknown')
            service = info.get('name', '') or ''
            product = info.get('product', '') or ''
            version = info.get('version', '') or ''
            extra = info.get('extrainfo', '') or ''
            print(f"{port:>6}  {state:>7}  {service:<12}  {product:<20}  {version:<12}  {extra}")

            product = product if product else service
            open_services.append((port, product, version))

    return open_services

def searchCVE(product, version, max_results=10): #data
    if not product:
        return {}

    query = f"{product} {version}".strip()
    params = {
        "keywordSearch": query,
        "resultsPerPage": str(max_results)
    }
    try:
        response = requests.get(NVD_API_URL, params=params, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"API Error: {response.status_code} – {response.text}")
            return {}
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return {}


def cveResults(data): #filters data
    results = []
    if not data:
        return results
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"] or cve.get("CVE_data_meta", {}).get("ID")
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        severity = "N/A"
        metrics = cve.get("metrics", {})
        try:
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                severity = metrics["cvssMetricV31"][0]["cvssData"].get("baseSeverity", "N/A")
            elif "cvssMetricV3" in metrics and metrics["cvssMetricV3"]:
                severity = metrics["cvssMetricV3"][0]["cvssData"].get("baseSeverity", "N/A")
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                severity = metrics["cvssMetricV2"][0]["cvssData"].get("baseSeverity", "N/A")
        except Exception:
            severity = "N/A"
        if cve_id:
            results.append((cve_id, severity, desc))
    return results


def vulScan(port, product, version): #works once per time

    if not product:
        print("  No product name found; skipping CVE lookup.")
        return (port, product, version, [])

    if product and not version:
        version = ""

    display_name = f"{product} {version}".strip()
    #debug
    #print(f"\nStarting CVE lookup for port {port}: {display_name or '(unknown)'}")

    data = searchCVE(product, version)
    cves = cveResults(data)

    if not cves and version :
        time.sleep(API_CALL_DELAY)
        print(f"\n CVE lookup for port {port}: {display_name or '(unknown)'}")
        print("  No CVEs found for exact version trying product-only search...")
        data = searchCVE(product, "")  # product only
        cves = cveResults(data)

    time.sleep(1.5)
    return (port, product, version, cves)
#return (port, product, version, cves, risk_score)


#-----MAIN--------------------------------------------------------------------

def main():

    #parser
    parser = argparse.ArgumentParser(
        description="Vulnerability Scanner with Risk Scoring"
    )
    parser.add_argument("--severity", choices=["LOW", "HIGH", "CRITICAL", "N/A"],
                        help="Show only vulnerabilities of this severity level")

    args = parser.parse_args()
    severity_filter = args.severity

    #port scanner
    ip_address = getIpAddress()
    open_services = nmapsV(ip_address)

#------------------------------------------------------------------------------

    #vulnerabilities scanner (CVE)
    if not open_services:
        print("\nNo open services to check for CVEs.")
        return

    print(f"\n{Style.BRIGHT}Checking CVEs for open services:{Style.RESET_ALL}")
    print("-" * 70)

    futures = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        for port, product, version in open_services:
            futures.append(executor.submit(vulScan, port, product, version))

        # gather results (port scanning)
        for future in as_completed(futures):
            try:
                port, product, version, cves = future.result()
            except Exception as e:
                print(f"[!] Worker error: {e}")
                continue

            if not product:
                print("  No product name found; skipped CVE lookup.")
                continue

            display_name = f"{product} {version}".strip() if version else product

            filtered_cves = []
            for cve_id, sev_raw, desc in cves:
                sev_up = (sev_raw or "N/A").upper()

                if not severity_filter:
                    match = True  #no filter -> keep all
                else:
                    sf = severity_filter.upper()
                    if sf == "HIGH":
                        match = sev_up in ("HIGH", "CRITICAL")
                    elif sf == "LOW":
                        match = sev_up in ("LOW", "N/A")
                    else:
                        #CRITICAL, "N/A"
                        match = sev_up == sf

                if match:
                    filtered_cves.append((cve_id, sev_up, desc))

            # Print results for this port
            if filtered_cves:
                port_label = f"{Style.BRIGHT}{Fore.YELLOW}Port {port} ->{Style.RESET_ALL}"
                for cve_id, severity, desc in filtered_cves:
                    cve_label = f"{Style.BRIGHT}{Fore.YELLOW}{cve_id}{Style.RESET_ALL}"
                    sev_color = color_for_severity(severity)
                    reset = Style.RESET_ALL + (Fore.RESET if hasattr(Fore, 'RESET') else "")

                    # port header
                    print(f"\n{port_label} {display_name or '(unknown)'}")
                    print(f"  {cve_label} | Severity: {sev_color}{severity}{reset}")
                    if desc:
                        print(f"    → {desc[:280].strip()}...")
            else:
                if severity_filter:
                    print(f"\n{Style.BRIGHT}{Fore.BLACK}Port {port} -> {display_name or '(unknown)'}: no CVEs at severity {severity_filter}{Style.RESET_ALL}")
                else:
                    print(f"\nPort {port} -> {display_name or '(unknown)'}: No known CVEs found for this product/version.")

    print(f"\n{Style.BRIGHT}{Fore.CYAN}DONE, filtering mode:{Style.RESET_ALL} {severity_filter.upper() if severity_filter else 'ALL'}")

if __name__ == "__main__":
    main()