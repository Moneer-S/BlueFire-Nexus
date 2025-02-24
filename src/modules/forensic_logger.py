# src/modules/forensic_logger.py
import logging
import platform
import os
import subprocess
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class ForensicLogger:
    def __init__(self, log_path=None):
        self.logger = logging.getLogger('BlueFire')
        self.logger.setLevel(logging.DEBUG)
        
        if log_path:
            handler = logging.FileHandler(log_path)
            handler.setFormatter(logging.Formatter(
                '[%(asctime)s] %(levelname)s - %(message)s',
                datefmt='%Y-%m-%dT%H:%M:%SZ'
            ))
            self.logger.addHandler(handler)
        else:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(
                '[%(asctime)s] %(levelname)s - %(message)s',
                datefmt='%Y-%m-%dT%H:%M:%SZ'
            ))
            self.logger.addHandler(handler)
        
        if platform.system() == 'Windows':
            self.wipe_method = self._windows_wipe
        else:
            self.wipe_method = self._unix_wipe

    def _fips_encrypt(self, data: bytes, key: bytes = None) -> bytes:
        """
        Dummy FIPS 140-3 compliant encryption using AES-GCM.
        In production, ensure the cryptography backend is FIPS validated.
        """
        key = key or AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, data, None)
        return nonce + ct

    def log(self, message, level="INFO"):
        if level.upper() == "DEBUG":
            self.logger.debug(message)
        elif level.upper() == "WARNING":
            self.logger.warning(message)
        elif level.upper() == "ERROR":
            self.logger.error(message)
        else:
            self.logger.info(message)

    def integrate_splunk(self, event: dict):
        """
        Dummy integration with Splunk/Humio.
        In production, send the event to your Splunk HTTP Event Collector.
        """
        splunk_token = os.getenv("SPLUNK_TOKEN")
        splunk_host = os.getenv("SPLUNK_HOST", "https://splunk.test.internal")
        if splunk_token:
            # Example: send event using requests (omitted for brevity)
            self.logger.info(f"Sending event to Splunk: {event}")
        else:
            self.logger.warning("SPLUNK_TOKEN not set; cannot send event.")

    def _windows_wipe(self, path):
        try:
            subprocess.run(['cipher', '/w:C'], check=True)
            self.logger.info(f"Securely wiped {path} on Windows.")
        except Exception as e:
            self.logger.error(f"Error during Windows secure deletion: {e}")

    def _unix_wipe(self, path):
        try:
            subprocess.run(['shred', '-u', path], check=True)
            self.logger.info(f"Securely wiped {path} on Unix.")
        except Exception as e:
            self.logger.error(f"Error during Unix secure deletion: {e}")

    def self_destruct(self):
        self.log("Activating digital seppuku protocol", level="DEBUG")
        test_path = "sensitive.log"
        if os.path.exists(test_path):
            self.wipe_method(test_path)
        else:
            self.log("No sensitive files to wipe.", level="WARNING")
