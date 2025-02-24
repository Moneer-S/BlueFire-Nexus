# src/core/dynamic_api.py
import ctypes
import json
import os
from ctypes import wintypes

class StealthAPIResolver:
    _kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    
    def __init__(self, hashes_file="api_hashes.json"):
        # Load API hashes from an external JSON file
        if os.path.exists(hashes_file):
            with open(hashes_file, "r") as f:
                self._hashes = json.load(f)
        else:
            self._hashes = {}  # Fallback to empty dictionary
            print("Warning: API hashes file not found. API resolution may fail.")
    
    def resolve(self, hash_val: str, argtypes=None, restype=None):
        """
        Resolve an API function based on its hash (as a string).
        """
        func_name = self._hashes.get(hash_val)
        if not func_name:
            raise ValueError(f"API hash {hash_val} not found")
        func = getattr(self._kernel32, func_name)
        func.argtypes = argtypes or []
        func.restype = restype or wintypes.BOOL
        return func

# Example usage:
if __name__ == "__main__":
    resolver = StealthAPIResolver()
    # Example: Resolve an API function using a sample hash "0xA3D82B19" (as a string)
    try:
        func = resolver.resolve("0xA3D82B19", argtypes=[wintypes.LPVOID], restype=wintypes.LPVOID)
        print("API function resolved:", func)
    except ValueError as e:
        print(e)
