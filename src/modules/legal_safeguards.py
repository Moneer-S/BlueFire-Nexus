# src/modules/legal_safeguards.py
import os
import requests

class EthicalCompliance:
    def __init__(self):
        self.killswitch_url = os.getenv(
            "BLUEFIRE_KILLSWITCH", 
            "http://localhost:8080/kill"
        )
        self.safe_mode = os.getenv("BLUEFIRE_SAFEMODE", "0") == "1"
        
    def check_abort(self):
        if self.safe_mode:
            return True
        try:
            resp = requests.get(
                self.killswitch_url, 
                timeout=3,
                headers={'User-Agent': 'BlueFire-Compliance-Check'}
            )
            return resp.status_code == 418  # Teapot status for validation
        except requests.RequestException:
            return False