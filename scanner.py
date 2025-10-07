import nmap
import ipaddress
import re
import sys
import requests
import time

NVD_API_KEY = ""
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}


def getIpAddress():
    while True:
        ip_add_entered = input("\nPlease enter the ip address that you want to scan: ").strip()
        try:
            ip_address_obj = ipaddress.ip_address(ip_add_entered)
            print("You entered a valid ip address.")
            return ip_address_obj
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
        result = nm.scan(ip_address, ports_spec, arguments='-sV')
    except Exception as e:
        print(f"Error running nmap: {e}")
        sys.exit(1)

    host_dict = result.get('scan', {}).get(ip_address, {})
    tcp_dict = host_dict.get('tcp', {})

    if not tcp_dict:
        print("No TCP info returned (host down or no open ports in that range).")
        sys.exit(0)

    # table output
    print("\nScan results:")
    print(f"{'PORT':>6}  {'STATE':>7}  {'SERVICE':<12}  {'PRODUCT':<20}  {'VERSION':<12}  {'EXTRA'}")
    print("-" * 80)

    for port, info in sorted(tcp_dict.items()):
        state = info.get('state', 'unknown')
        service = info.get('name', '') or ''
        product = info.get('product', '') or ''
        version = info.get('version', '') or ''
        extra = info.get('extrainfo', '') or ''

        print(f"{port:>6}  {state:>7}  {service:<12}  {product:<20}  {version:<12}  {extra}")

        if state != 'open' :
            continue

        result_product = product if product else service
        result_version = version

        print(f"Port {port} is open: product={result_product!r}, version={result_version!r}")

        return result_product, result_version


def searchCVE(product, version):
    query = f"{product} {version}"
    params = {
        "keywordSearch": query,
        "resultsPerPage": 10
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


def cveResults(data):
    results = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]
        desc = cve["descriptions"][0]["value"]
        severity = "N/A"
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        elif "cvssMetricV2" in metrics:
            severity = metrics["cvssMetricV2"][0]["cvssData"]["baseSeverity"]
        results.append((cve_id, severity, desc))
    return results

def main():

    #port scanner
    ip_address = getIpAddress()
    port_min, port_max = getRange()

    result_product, result_version = nmapsV(ip_address, port_min, port_max)

    #vulnerabilities scanner (CVE)
    print(f"\n Scanning: {result_product} {result_version}")
    data = searchCVE(result_product, result_version)
    cves = cveResults(data)

    if cves:
        for cve_id, severity, desc in cves:
            print(f"\n {cve_id} | Severity: {severity}")
            print(f"→ {desc[:150]}...")
    else:
        print("\n No known CVEs found for this service and version.")

    time.sleep(1.5)




