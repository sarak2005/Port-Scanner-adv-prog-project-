import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.network import get_ip_input
from scanner.port_scanner import PortScanner
from scanner.cve_scanner import CVEScanner
from ui.observers import ScanSubject, ConsoleObserver
from ui.colors import Style, Fore
from ui.output import display_results


def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability Scanner with Risk Scoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        #filters
        epilog="""
Examples:
  %(prog)s                         # Interactive mode
  %(prog)s --severity CRITICAL     # Show only critical vulnerabilities
  %(prog)s --severity HIGH         # Show high and critical vulnerabilities
        """
    )

    parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL", "N/A"],
        help="Filter results by severity level"
    )

    args = parser.parse_args()

    # Initialize components
    port_scanner = PortScanner()
    cve_scanner = CVEScanner()
    scan_subject = ScanSubject()
    scan_subject.attach(ConsoleObserver())

    #get target IP (ip input)
    print(f"{Style.BRIGHT}{Fore.CYAN}=== Vulnerability Scanner ==={Style.RESET_ALL}")
    ip_address = get_ip_input()

    #port scan
    open_services = port_scanner.scan(ip_address)

    if not open_services:
        print("\nNo open services found.")
        return

    #vulnerabilities scan
    print(f"\n{Style.BRIGHT}Checking for vulnerabilities...{Style.RESET_ALL}")

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for port, product, version in open_services:
            future = executor.submit(
                scan_service,
                port, product, version,
                cve_scanner, scan_subject, args.severity
            )
            futures.append(future)

        # Wait for all scans to complete
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Error during scan: {e}")

    print(f"\n{Style.BRIGHT}{Fore.GREEN}Scan completed!{Style.RESET_ALL}")


#scan a single service for vulnerabilities
def scan_service(port, product, version, cve_scanner, scan_subject, severity_filter):
    cves = cve_scanner.scan_product(product, version)

    #severity filter (if specified)
    if severity_filter:
        cves = filter_by_severity(cves, severity_filter)

    scan_subject.notify(port, product, version, cves)


def filter_by_severity(cves, target_severity):
    target = target_severity.upper()

    severity_groups = {
        "CRITICAL": ["CRITICAL"],
        "HIGH": ["HIGH", "CRITICAL"],
        "MEDIUM": ["MEDIUM"],
        "LOW": ["LOW", "N/A"],
        "N/A": ["N/A"]
    }

    allowed = severity_groups.get(target, [])
    return [cve for cve in cves if cve[1] in allowed]


if __name__ == "__main__":
    main()