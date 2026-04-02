import requests
import os
import time
from dotenv import load_dotenv

load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY")
_cache = {"data": None, "timestamp": 0}
CACHE_DURATION = 600

def get_critical_cves(limit=20):
    global _cache
    now = time.time()
    if _cache["data"] and (now - _cache["timestamp"]) < CACHE_DURATION:
        print("Using cached CVE data.")
        return _cache["data"]

    print("Fetching CVEs from NVD...")
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "cvssV3Severity": "CRITICAL",
            "resultsPerPage": limit,
            "sortBy": "published",
            "sortOrder": "dsc"
        }
        headers = {"apiKey": NVD_API_KEY}
        response = requests.get(url, params=params, headers=headers, timeout=10)

        if response.status_code == 429:
            print("Rate limited. Using fallback data.")
            return get_fallback_cves()

        if response.status_code != 200:
            print(f"Error: {response.status_code}. Using fallback data.")
            return get_fallback_cves()

        data = response.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            cves.append({
                "id": cve["id"],
                "description": cve["descriptions"][0]["value"],
                "published": cve["published"][:10],
                "severity": "CRITICAL"
            })

        _cache["data"] = cves
        _cache["timestamp"] = now
        print(f"Fetched {len(cves)} CVEs.")
        return cves

    except Exception as e:
        print(f"Error: {e}. Using fallback data.")
        return get_fallback_cves()


def get_fallback_cves():
    return [
        {"id": "CVE-2024-21413", "description": "Microsoft Outlook Remote Code Execution Vulnerability allows attackers to execute arbitrary code via a specially crafted email.", "published": "2024-02-13", "severity": "CRITICAL"},
        {"id": "CVE-2024-3400", "description": "PAN-OS command injection vulnerability in GlobalProtect Gateway allows unauthenticated remote code execution.", "published": "2024-04-12", "severity": "CRITICAL"},
        {"id": "CVE-2023-44487", "description": "HTTP/2 Rapid Reset Attack enables distributed denial of service by exploiting stream cancellation.", "published": "2023-10-10", "severity": "CRITICAL"},
        {"id": "CVE-2024-1709", "description": "ConnectWise ScreenConnect authentication bypass vulnerability allows full system compromise without credentials.", "published": "2024-02-21", "severity": "CRITICAL"},
        {"id": "CVE-2024-21762", "description": "Fortinet FortiOS out-of-bounds write vulnerability allows remote unauthenticated attackers to execute arbitrary code.", "published": "2024-02-08", "severity": "CRITICAL"},
    ]
