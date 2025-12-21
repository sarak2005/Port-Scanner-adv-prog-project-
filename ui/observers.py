from abc import ABC, abstractmethod
from typing import List, Tuple
from ui.colors import Style, Fore

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

        if cves:
            print(f"\nPort {port} → {display_name}: {len(cves)} CVEs found")
            for cve_id, severity, desc in cves:
                print(f"  {cve_id} | Severity: {severity} | {desc[:80]}...")
        else:
            print(f"\nPort {port} → {display_name}: No CVEs found")


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