# src/modules/legal_safeguards.py
class EthicalCompliance:
    KILLSWITCH_URL = "http://localhost:8080/kill"  # Test endpoint
    
    def check_abort(self):
        if self.safe_mode:
            return True
        try:
            resp = requests.get(self.KILLSWITCH_URL, timeout=5)
            return resp.status_code == 418  # Use tea status for test
        except:
            return False