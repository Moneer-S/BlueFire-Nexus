# archive/forensic_logger.py
# (Originally src/modules/forensic_logger.py)
import logging
import platform
import os
import subprocess
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Note: This appears to be a standalone logging utility with some
# specific features like secure wipe and Splunk integration placeholders.
# It doesn't seem to be integrated into the main BlueFireNexus core logging.

class ForensicLogger:
    def __init__(self, log_path=None):
        self.logger = logging.getLogger('BlueFire_Forensic') # Use a distinct name
        self.logger.setLevel(logging.DEBUG)
        
        # Avoid adding handlers if logger already has them (e.g., in interactive use)
        if not self.logger.handlers:
            if log_path:
                handler = logging.FileHandler(log_path)
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
        # Note: Telemetry seems handled in config.yaml / core modules now.
        splunk_token = os.getenv("SPLUNK_TOKEN")
        splunk_host = os.getenv("SPLUNK_HOST", "https://splunk.test.internal")
        if splunk_token and splunk_host:
            # Example: send event using requests (omitted for brevity)
            # import requests
            # headers = {'Authorization': f'Splunk {splunk_token}'}
            # try:
            #    requests.post(f"{splunk_host}/services/collector/event", json={'event': event}, headers=headers, verify=False)
            self.logger.info(f"Sending event to Splunk: {event}")
            # except Exception as e:
            #    self.logger.error(f"Failed to send event to Splunk: {e}")
        else:
            self.logger.warning("SPLUNK_TOKEN or SPLUNK_HOST not set; cannot send event.")

    def _windows_wipe(self, path):
        try:
            # Note: cipher /w only works on directories, not individual files.
            # For files, overwrite + rename + delete is more common.
            # This might be intended for a log directory.
            subprocess.run(['cipher', '/w:' + os.path.dirname(path)], check=True, capture_output=True)
            # Attempt to delete the specific file after wiping the directory free space
            if os.path.exists(path):
                 os.remove(path)
            self.logger.info(f"Attempted secure wipe near {path} on Windows.")
        except Exception as e:
            self.logger.error(f"Error during Windows secure deletion near {path}: {e}")

    def _unix_wipe(self, path):
        try:
            # shred is a good option if available
            subprocess.run(['shred', '-zuf', path], check=True, capture_output=True)
            self.logger.info(f"Securely wiped {path} on Unix using shred.")
        except FileNotFoundError: # Fallback if shred isn't available
             try:
                 # Simple overwrite (less secure but better than nothing)
                 with open(path, 'wb') as f:
                     f.write(os.urandom(os.path.getsize(path)))
                 os.remove(path)
                 self.logger.info(f"Wiped {path} on Unix using overwrite.")
             except Exception as e:
                 self.logger.error(f"Error during Unix secure deletion fallback for {path}: {e}")
        except Exception as e:
            self.logger.error(f"Error during Unix secure deletion for {path}: {e}")

    def self_destruct(self, file_to_wipe: str):
        self.log(f"Activating self-destruct protocol for {file_to_wipe}", level="WARNING")
        if os.path.exists(file_to_wipe):
            self.wipe_method(file_to_wipe)
        else:
            self.log(f"File not found, cannot self-destruct: {file_to_wipe}", level="ERROR") 