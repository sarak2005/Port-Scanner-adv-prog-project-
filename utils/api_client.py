import requests
import time
from typing import Optional, Dict
from config import NVD_API_URL, HEADERS, API_CALL_DELAY


class NVDClient:
    def __init__(self):
        self.base_url = NVD_API_URL
        self.headers = HEADERS
        self.delay = API_CALL_DELAY

    #search cve
    def search_cves(self, product: str, version: str = "", max_results: int = 10) -> Optional[Dict]:
        if not product:
            return None

        query = f"{product} {version}".strip()
        params = {
            "keywordSearch": query,
            "resultsPerPage": str(max_results)
        }

        try:
            response = requests.get(
                self.base_url,
                params=params,
                headers=self.headers,
                timeout=15
            )
            response.raise_for_status()
            time.sleep(self.delay)  # Rate limiting
            return response.json()
        except requests.RequestException as e:
            print(f"API request failed: {e}")
            return None