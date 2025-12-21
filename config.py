import os

# API Configuration
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_CALL_DELAY = 0.6

# Headers for API requests
HEADERS = {}
if NVD_API_KEY:
    HEADERS["apiKey"] = NVD_API_KEY


# Nmap Configuration
DEFAULT_NMAP_ARGS = {
    'base_scan': '-sS' if os.geteuid() == 0 else '-sT',
    'timing': '-T4',
    'min_rate': '--min-rate 1000',
    'max_retries': '--max-retries 1',
    'timeout': '--host-timeout 60s'
}

# Risk scoring weights
RISK_WEIGHTS = {
    'CRITICAL': 10,
    'HIGH': 8,
    'MEDIUM': 5,
    'LOW': 2,
    'N/A': 0
}

HIGH_RISK_PORTS = [21, 22, 23, 25, 80, 443, 445, 3389]