from typing import List, Tuple
from ui.colors import Style, Fore, color_for_severity


#ports/services
def display_results(open_services: List[Tuple], severity_filter: str = None):
    if not open_services:
        print("\nNo open services found.")
        return

    print(f"\n{Style.BRIGHT}Vulnerability Scan Results:{Style.RESET_ALL}")
    print("=" * 70)

    for port, product, version in open_services:
        display_name = f"{product} {version}".strip() if version else product
        port_label = f"{Style.BRIGHT}{Fore.CYAN}Port {port} →{Style.RESET_ALL}"

        print(f"\n{port_label} {display_name or '(unknown service)'}")


#cve
def format_cve_entry(cve_id: str, severity: str, description: str) -> str:
    sev_color = color_for_severity(severity)
    return (f"  {Fore.YELLOW}{cve_id}{Style.RESET_ALL} | "
            f"Severity: {sev_color}{severity}{Style.RESET_ALL} | "
            f"{description[:100]}...")