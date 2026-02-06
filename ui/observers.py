from abc import ABC, abstractmethod
from typing import List, Tuple
from ui.colors import Style, Fore, color_for_severity


#Observer pattern for scan results

#abstract for future-proofing
class ScanObserver(ABC):
    @abstractmethod
    def update(self, port: int, product: str, version: str, cves: List[Tuple]):
        pass

#implemntation
class ConsoleObserver(ScanObserver):
    def update(self, port: int, product: str, version: str, cves: List[Tuple]):
        display_name = f"{product} {version}".strip() if version else product
        port_label = f"{Style.BRIGHT}{Fore.YELLOW}Port {port} ->{Style.RESET_ALL}"

        if cves:
            # Print port header ONCE
            print(f"\n{port_label} → {display_name}:")

            # Then list all CVEs
            for cve_id, severity, desc in cves:
                cve_label = f"{Style.BRIGHT}{Fore.MAGENTA}{cve_id}{Style.RESET_ALL}"
                sev_color = color_for_severity(severity)
                reset = Style.RESET_ALL + (Fore.RESET if hasattr(Fore, 'RESET') else "")

                print(f"  {cve_label} | Severity: {sev_color}{severity}{reset}")
                if desc:
                    print(f"    → {desc[:280].strip()}...")

            # Optional: Show count
            print(f"  {Style.DIM}Total: {len(cves)} vulnerability(ies){Style.RESET_ALL}")
        else:
            print(f"\n{port_label} → {display_name}: No CVEs found")


class ScanSubject:
    def __init__(self):
        self.observers = []

    def attach(self, observer: ScanObserver):
        self.observers.append(observer)

    def detach(self, observer: ScanObserver):
        self.observers.remove(observer)

    def notify(self, port: int, product: str, version: str, cves: List[Tuple]):
        for observer in self.observers:
            observer.update(port, product, version, cves)