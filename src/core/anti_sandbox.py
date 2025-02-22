import ctypes
import platform
import psutil

class EnvironmentValidator:
    @staticmethod
    def is_debugging() -> bool:
        try:
            return ctypes.windll.kernel32.IsDebuggerPresent() != 0
        except:  # Fail on non-Windows
            return False

    @staticmethod
    def check_memory() -> bool:
        return psutil.virtual_memory().total >= 4 * 1024**3  # 4GB RAM check

    @staticmethod  
    def detect_sandbox() -> bool:
        blacklist = {
            'hostname': ['SANDBOX', 'VIRUS'],
            'mac': ['00:1C:42', '00:0C:29'],
            'processes': ['vmtoolsd.exe', 'procmon.exe']
        }
        
        # Hostname check
        if platform.node().upper() in blacklist['hostname']:
            return True
            
        # MAC check
        for nic, addrs in psutil.net_if_addrs().items():
            if any(a.address[:8] in blacklist['mac'] for a in addrs):
                return True
                
        # Process check        
        return any(p.name().lower() in blacklist['processes'] 
            for p in psutil.process_iter(['name']))