from typing import List, Tuple
from utils.api_client import NVDClient

#CVE lookup
class CVEScanner:
    def __init__(self):
        self.api_client = NVDClient()

    #scan for cves - return list of tuples (cve_id, severity, description)
    def scan_product(self, product: str, version: str = "") -> List[Tuple]:
        if not product:
            return []

        data = self.api_client.search_cves(product, version)
        return self._parse_cve_data(data)

    #Extract cve infos from API response
    def _parse_cve_data(self, data: dict) -> List[Tuple]:
        if not data:
            return []

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")

            if not cve_id:
                continue

            description = self._get_english_description(cve)

            severity = self._extract_severity(cve)

            cves.append((cve_id, severity, description))

        return cves


    #helper functions
    def _get_english_description(self, cve_data: dict) -> str:
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                return desc.get("value", "")
        return ""

    def _extract_severity(self, cve_data: dict) -> str:
        metrics = cve_data.get("metrics", {})

        # Try different CVSS versions in order
        for version in ["cvssMetricV31", "cvssMetricV3", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                try:
                    return metrics[version][0]["cvssData"].get("baseSeverity", "N/A")
                except (KeyError, IndexError):
                    continue

        return "N/A"