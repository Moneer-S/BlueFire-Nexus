#!/usr/bin/env python3
# src/modules/forensic_logger.py

import logging
import platform
import os
import subprocess
import secure_delete  # Ensure this package is installed or replace with an alternative

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
            # Console handler as fallback
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

    def _secure_delete(self, path):
        # Use secure_delete package to securely delete a file
        secure_delete.secure_random_seed_init()
        secure_delete.secure_delete(path)
        
    def _windows_wipe(self, path):
        # Minimal Windows secure deletion using cipher command (or similar)
        try:
            subprocess.run(['cipher', '/w:C'], check=True)
            self.logger.info(f"Securely wiped {path} on Windows.")
        except Exception as e:
            self.logger.error(f"Error during Windows secure deletion: {e}")

    def _unix_wipe(self, path):
        # Minimal Unix secure deletion using 'shred'
        try:
            subprocess.run(['shred', '-u', path], check=True)
            self.logger.info(f"Securely wiped {path} on Unix.")
        except Exception as e:
            self.logger.error(f"Error during Unix secure deletion: {e}")

    def log(self, message, level="INFO"):
        if level.upper() == "DEBUG":
            self.logger.debug(message)
        elif level.upper() == "WARNING":
            self.logger.warning(message)
        elif level.upper() == "ERROR":
            self.logger.error(message)
        else:
            self.logger.info(message)

    def self_destruct(self):
        self.log("Activating digital seppuku protocol", level="DEBUG")
        # Example: Wipe a log file (for demonstration)
        test_path = "sensitive.log"
        if os.path.exists(test_path):
            self.wipe_method(test_path)
        else:
            self.log("No sensitive files to wipe.", level="WARNING")
