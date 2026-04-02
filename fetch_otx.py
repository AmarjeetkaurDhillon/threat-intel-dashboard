import requests
import os
from dotenv import load_dotenv

load_dotenv()

OTX_API_KEY = os.getenv("OTX_API_KEY")

def get_threat_indicators():
    print("Fetching OTX threat indicators...")
    try:
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code != 200:
            print(f"OTX Error: {response.status_code}. Using fallback.")
            return get_fallback_indicators()

        data = response.json()
        indicators = []

        for pulse in data.get("results", [])[:5]:
            for indicator in pulse.get("indicators", [])[:3]:
                if indicator["type"] in ["IPv4", "domain", "URL", "hostname"]:
                    indicators.append({
                        "type": indicator["type"],
                        "indicator": indicator["indicator"],
                        "pulse": pulse["name"],
                        "created": pulse["created"][:10]
                    })

        if not indicators:
            return get_fallback_indicators()

        print(f"Fetched {len(indicators)} threat indicators.")
        return indicators[:15]

    except Exception as e:
        print(f"OTX error: {e}. Using fallback.")
        return get_fallback_indicators()


def get_fallback_indicators():
    return [
        {"type": "IPv4", "indicator": "185.220.101.45", "pulse": "Tor Exit Node — Malicious Activity", "created": "2024-03-01"},
        {"type": "IPv4", "indicator": "194.165.16.77", "pulse": "Cobalt Strike C2 Server", "created": "2024-03-05"},
        {"type": "domain", "indicator": "malware-update.net", "pulse": "Phishing Campaign 2024", "created": "2024-02-28"},
        {"type": "IPv4", "indicator": "91.92.251.103", "pulse": "Ransomware Distribution", "created": "2024-03-10"},
        {"type": "domain", "indicator": "secure-login-verify.com", "pulse": "Banking Trojan Campaign", "created": "2024-03-08"},
        {"type": "hostname", "indicator": "cdn.update-service.ru", "pulse": "APT29 Infrastructure", "created": "2024-03-12"},
        {"type": "IPv4", "indicator": "45.142.212.100", "pulse": "Emotet Botnet C2", "created": "2024-03-15"},
        {"type": "domain", "indicator": "microsoft-verify.xyz", "pulse": "Credential Harvesting Campaign", "created": "2024-03-18"},
        {"type": "IPv4", "indicator": "103.43.75.50", "pulse": "DDoS Botnet Node", "created": "2024-03-20"},
        {"type": "domain", "indicator": "paypal-secure-update.net", "pulse": "Phishing Campaign 2024", "created": "2024-03-22"},
    ]