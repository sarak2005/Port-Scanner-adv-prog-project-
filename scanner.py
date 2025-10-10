import nmap
import ipaddress
import re
import sys
import requests
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed


NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
API_CALL_DELAY = 0.6


def getIpAddress():
    while True:
        ip_add_entered = input("\nPlease enter the ip address that you want to scan: ").strip()
        try:
            ip_address_obj = ipaddress.ip_address(ip_add_entered)
            print("You entered a valid ip address.")
            return str(ip_address_obj)
        except Exception:
            print("You entered an invalid ip address. Try again.")

def getRange():
    port_range_pattern = re.compile(r"([0-9]+)-([0-9]+)")
    port_min = 0
    port_max = 65535

    while True:
        print("Please enter the range of ports you want to scan in format: <int>-<int>")
        port_range = input("Enter port range: ").strip()
        port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
        if port_range_valid:
            port_min = int(port_range_valid.group(1))
            port_max = int(port_range_valid.group(2))
            if 0 <= port_min <= 65535 and 0 <= port_max <= 65535 and port_min <= port_max:
                return port_min, port_max
            else:
                print("Port numbers must be between 0 and 65535 and start <= end. Try again.")
        else:
            print("Invalid format")

def nmapsV(ip_address, port_min, port_max):
    nm = nmap.PortScanner()
    ports_spec = f"{port_min}-{port_max}"
    print(f"\nRunning nmap -sV on {ip_address} ports {ports_spec} ... (this may take a bit)")

    try:
        result = nm.scan(hosts=ip_address, ports="1-65535", arguments='-sS --open -T4')
    except Exception as e:
        print(f"Error running nmap: {e}")
        sys.exit(1)


    #open ports
    open_ports = []
    if ip_address in nm.all_hosts():
        if 'tcp' in nm[ip_address]:
            for port, info in nm[ip_address]['tcp'].items():
                if info.get('state') == 'open':
                    open_ports.append(str(port))

    if not open_ports:
        print("No open TCP ports found.")
    else:
        port_list = ",".join(open_ports)
        print("Open ports:", port_list)


    # service/version detection

    # table output
    print("\nScan results:")
    print(f"{'PORT':>6}  {'STATE':>7}  {'SERVICE':<12}  {'PRODUCT':<20}  {'VERSION':<12}  {'EXTRA'}")
    print("-" * 90)

    open_services = []
    nm.scan(hosts=ip_address, ports=port_list, arguments='-sV -T3')
    for port, info in nm[ip_address]['tcp'].items():
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
    print(f"\nStarting CVE lookup for port {port}: {display_name or '(unknown)'}")

    data = searchCVE(product, version)
    cves = cveResults(data)

    if not cves and version :
        time.sleep(API_CALL_DELAY)
        print("  No CVEs found for exact version trying product-only search...")
        data = searchCVE(product, "")  # product only
        cves = cveResults(data)

    time.sleep(1.5)
    return (port, product, version, cves)


def main():

    #port scanner
    ip_address = getIpAddress()
    port_min, port_max = getRange()
    open_services = nmapsV(ip_address, port_min, port_max)

#------------------------------------------------------------------------------

    #vulnerabilities scanner (CVE)
    if not open_services:
        print("\nNo open services to check for CVEs.")
        return

    print("\nChecking CVEs for open services:")
    print("-" * 70)

    futures = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        for port, product, version in open_services:
            futures.append(executor.submit(vulScan, port, product, version))

    for future in as_completed(futures):
        try:
            port, product, version, cves = future.result()
        except Exception as e:
            print(f"[!] Worker error: {e}")
            continue

        display_name = f"{product} {version}".strip() if version else product
        print(f"\nPort {port} -> {display_name or '(unknown)'}")

        if not product:
            print("  No product name found; skipped CVE lookup.")
            continue

        if cves:
            for cve_id, severity, desc in cves:
                print(f"  {cve_id} | Severity: {severity}")
                if desc:
                    print(f"    → {desc[:280].strip()}...")
        else:
            print(" No known CVEs found for this product/version.")

    print("\nAll done.")



if __name__ == "__main__":
    main()