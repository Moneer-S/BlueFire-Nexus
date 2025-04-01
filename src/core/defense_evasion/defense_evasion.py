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
from pathlib import Path # Used by timestomp

# Imports needed for PID Spoofing
if platform.system() == "Windows":
    import ctypes
    from ctypes import wintypes
    import win32con
    import win32api
    import win32process
    import pywintypes # For error handling

# Import OS-specific handlers
from .windows_defense_evasion import WindowsDefenseEvasion
from .linux_defense_evasion import LinuxDefenseEvasion
from .macos_defense_evasion import MacOSDefenseEvasion

# Avoid circular import for type hinting
if TYPE_CHECKING:
    from ..execution.execution import Execution
    # Cannot import BlueFireNexus here due to circular dependency
    # Use string literal for type hint if needed, or alternative structure
    # from .bluefire_nexus import BlueFireNexus

logger = logging.getLogger(__name__)

class DefenseEvasion:
    """Handles defense evasion techniques by dispatching to OS-specific handlers."""

    # Removed nexus_instance from __init__ to avoid circular import
    # Pass execution module instead
    def __init__(self, execution_module: 'Execution'):
        # self.nexus = nexus_instance # Removed
        self.execution_module = execution_module
        self.os_type = platform.system()
        self.os_handler = None
        self.config = {
            "default_timestomp_mode": "mimic",
            "default_timestomp_source": None,
            "default_time_format": "%Y-%m-%d %H:%M:%S",
        }

        if not execution_module:
            logger.error("DefenseEvasion module initialized WITHOUT Execution module. Some techniques may fail.")
            # Define a dummy _execute_command to prevent errors later?
            def _dummy_execute(*args, **kwargs):
                logger.error("Execution module unavailable, cannot execute commands.")
                return {"status": "failure", "reason": "Execution module unavailable"}
            self._execute_command = _dummy_execute
        else:
            # Wrapper function to ensure consistent execution call signature
            def _execute_command_wrapper(command: str, method: str = "direct", capture: bool = True) -> Dict[str, Any]:
                exec_data = {"execute": {"command": {"cmd": command, "method": method, "capture_output": capture}}}
                try:
                    exec_result = self.execution_module.execute(exec_data)
                    # Extract the inner command execution result
                    cmd_exec_result = exec_result.get("results", {}).get("command_execution", {})
                    # Ensure a status is present
                    if "status" not in cmd_exec_result:
                         cmd_exec_result["status"] = "unknown"
                    return cmd_exec_result
                except Exception as e:
                    logger.error(f"Failed to execute command '{command}' via Execution module: {e}", exc_info=True)
                    return {"status": "failure", "reason": f"Execution failed: {e}"}
            self._execute_command = _execute_command_wrapper

        # Instantiate the appropriate OS handler
        if self.os_type == "Windows":
            self.os_handler = WindowsDefenseEvasion(self._execute_command)
        elif self.os_type == "Linux":
            self.os_handler = LinuxDefenseEvasion(self._execute_command)
        elif self.os_type == "Darwin":
            self.os_handler = MacOSDefenseEvasion(self._execute_command)
        else:
            logger.error(f"Unsupported OS for DefenseEvasion module: {self.os_type}")
            self.os_handler = None

        # Define supported techniques - combine general and OS-specific
        self.general_techniques = {
             "argument_spoofing": self._handle_argument_spoofing,
             "timestomp": self._timestomp_file, # Keep timestomp general for now
             "process_evasion": self._handle_process_evasion, # Placeholder
             "network_evasion": self._handle_network_evasion, # Placeholder
        }
        self.os_supported_techniques = self.os_handler.handler_map.keys() if self.os_handler else []
        self.supported_techniques = list(self.general_techniques.keys()) + list(self.os_supported_techniques)
        logger.info(f"Supported defense evasion techniques on {self.os_type}: {self.supported_techniques}")


    def update_config(self, config: Dict[str, Any]):
        """Update internal config with loaded configuration."""
        self.config.update(config.get("defense_evasion", {}))
        logger.info("DefenseEvasion module configuration updated.")

    def run_evasion(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Route defense evasion requests to appropriate handlers."""
        result = {"status": "failure", "reason": "No technique specified"}
        errors = []
        results_map = {}

        evasion_requests = data.get("evade", {}) # Allow single or list? Assume single for now
        technique = evasion_requests.get("technique")
        details = evasion_requests.get("details", {})

        if not technique:
            return {"status": "error", "message": "Missing 'technique' in evasion request data."}

        handler = None
        is_os_specific = False

        # Check general handlers first
        if technique in self.general_techniques:
            handler = self.general_techniques[technique]
        # Check OS-specific handlers if available
        elif self.os_handler and technique in self.os_handler.handler_map:
            handler = self.os_handler.evade # Call the dispatch method
            is_os_specific = True
        # Handle sub-techniques like file_evasion actions
        elif technique == "file_evasion":
             action = details.get("action")
             if action == "hide" and self.os_handler and "file_hide" in self.os_handler.handler_map:
                 handler = self.os_handler.evade
                 technique = "file_hide" # Adjust technique for OS handler dispatch
                 is_os_specific = True
             elif action == "timestomp":
                 # Timestomp currently handled by general handler
                 handler = self._timestomp_file
                 technique = "timestomp" # Adjust technique name
             else:
                  error_msg = f"Unsupported file evasion action '{action}' or OS handler unavailable."
                  errors.append(error_msg)
                  results_map[technique] = {"status": "error", "message": error_msg}
        else:
            error_msg = f"Unsupported or unknown evasion technique requested: {technique}"
            errors.append(error_msg)
            results_map[technique] = {"status": "error", "message": error_msg}

        if handler:
            try:
                if is_os_specific:
                    # OS handler's evade method expects technique name
                    evasion_result = handler(technique, details)
                else:
                    # General handlers directly process details
                    evasion_result = handler(details)
                
                results_map[technique] = evasion_result # Store result under the (potentially adjusted) technique name
                if evasion_result.get("status") == "failure":
                    errors.append(f"Technique '{technique}' failed: {evasion_result.get('reason', 'Unknown reason')}")
            except Exception as e:
                error_msg = f"Evasion technique '{technique}' execution failed: {e}"
                errors.append(error_msg)
                logger.error(error_msg, exc_info=True)
                results_map[technique] = {"status": "error", "reason": str(e)}

        # Determine overall status
        final_status = "success"
        if errors:
            all_failed = all(res.get("status") != "success" for res in results_map.values())
            final_status = "failure" if all_failed else "partial_success"
        elif not results_map: # No handler found or ran
             final_status = "failure"
             errors.append("No technique executed.")

        return {
            "status": final_status,
            "timestamp": datetime.now().isoformat(),
            "results": results_map,
            "errors": errors if errors else None
        }


    # --- General Handlers (Cross-Platform or Dispatchers) ---

    def _handle_file_evasion(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Handle file evasion techniques like hiding and timestomping - Now dispatches."""
        target_file = details.get("target_file")
        action = details.get("action", "hide") # hide, timestomp

        if not target_file or not os.path.exists(target_file):
             return {"status": "error", "reason": f"Target file '{target_file}' not provided or does not exist."}

        self.logger.info(f"Handling file evasion action '{action}' on target: {target_file}")

        if action == "hide":
            if self.os_handler and "file_hide" in self.os_handler.handler_map:
                return self.os_handler.evade("file_hide", details)
            else:
                return {"status": "not_implemented", "reason": f"File hiding not supported on {self.os_type}"}
        elif action == "timestomp":
            # Timestomp logic is relatively cross-platform, keep here for now
            return self._timestomp_file(details)
        else:
            return {"status": "error", "reason": f"Unsupported file evasion action: {action}"}


    def _timestomp_file(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Modify file access, modification, and creation times."""
        target_file = details.get("target_file")
        if not target_file or not os.path.exists(target_file):
             return {"status": "error", "reason": f"Target file '{target_file}' not provided or does not exist."}
             
        mode = details.get("mode", self.config.get("default_timestomp_mode", "mimic"))
        source_file = details.get("source_file", self.config.get("default_timestomp_source"))
        access_time_str = details.get("access_time")
        modify_time_str = details.get("modify_time")
        time_format = self.config.get("default_time_format")

        result_details = {"target_file": target_file, "mode": mode}
        status = "failure"
        mitre_id = "T1070.006"
        mitre_name = "Indicator Removal: Timestomp"

        access_time_ts = None
        modify_time_ts = None

        self.logger.info(f"Attempting timestomp on {target_file} using mode: {mode}")

        try:
            if mode == "mimic":
                if not source_file or not os.path.exists(source_file):
                     reason = f"Source file '{source_file}' for mimic mode not provided or does not exist."
                     result_details["reason"] = reason
                     self.logger.error(reason)
                     return {"status": "error", "reason": reason, "details": result_details, "mitre_technique_id": mitre_id, "mitre_technique_name": mitre_name}

                result_details["source_file"] = source_file
                stat_result = os.stat(source_file)
                access_time_ts = stat_result.st_atime
                modify_time_ts = stat_result.st_mtime
                self.logger.info(f"Mimicking timestamps from {source_file}: AT={access_time_ts}, MT={modify_time_ts}")

            elif mode == "specific_time":
                try:
                    current_stat = os.stat(target_file)
                    # Use current times as default if specific ones aren't provided
                    access_time_ts = current_stat.st_atime
                    modify_time_ts = current_stat.st_mtime

                    if access_time_str:
                        access_time_dt = datetime.strptime(access_time_str, time_format)
                        access_time_ts = access_time_dt.timestamp()
                    if modify_time_str:
                        modify_time_dt = datetime.strptime(modify_time_str, time_format)
                        modify_time_ts = modify_time_dt.timestamp()

                    if not access_time_str and not modify_time_str:
                         self.logger.warning("Neither access_time nor modify_time provided for specific_time mode. Using current times.")

                    self.logger.info(f"Using specific timestamps: AT={access_time_ts}, MT={modify_time_ts}")

                except ValueError as e:
                     reason = f"Invalid time format for specific_time mode: {e}. Expected format: {time_format}"
                     result_details["reason"] = reason
                     self.logger.error(reason)
                     return {"status": "error", "reason": reason, "details": result_details, "mitre_technique_id": mitre_id, "mitre_technique_name": mitre_name}

            # Add "random_within_range" mode later if needed

            else:
                 reason = f"Unsupported timestomp mode: {mode}"
                 result_details["reason"] = reason
                 self.logger.error(reason)
                 return {"status": "error", "reason": reason, "details": result_details, "mitre_technique_id": mitre_id, "mitre_technique_name": mitre_name}

            # Apply the timestamps using os.utime
            if access_time_ts is not None and modify_time_ts is not None:
                 os.utime(target_file, (access_time_ts, modify_time_ts))
                 # Verification (optional)
                 new_stat = os.stat(target_file)
                 if abs(new_stat.st_atime - access_time_ts) < 1 and abs(new_stat.st_mtime - modify_time_ts) < 1:
                      status = "success"
                      result_details["applied_access_time"] = access_time_ts
                      result_details["applied_modify_time"] = modify_time_ts
                      self.logger.info(f"Successfully timestomped {target_file}.")
                 else:
                      reason = "os.utime completed but verification of timestamps failed."
                      result_details["reason"] = reason
                      self.logger.error(reason)
            else:
                 reason = "Could not determine timestamps to apply."
                 result_details["reason"] = reason
                 self.logger.error(reason)

        except Exception as e:
            reason = f"Unexpected error during timestomp: {e}"
            result_details["reason"] = reason
            self.logger.error(reason, exc_info=True)
            status = "error"

        return {
            "status": status,
            "technique": "timestomp", # Keep specific technique name
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "details": result_details
        }

    def _handle_argument_spoofing(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate Argument Spoofing by manipulating command line before execution."""
        original_command = details.get("command")
        spoofed_command = details.get("spoofed_command") # How the command should appear in logs
        execution_method = details.get("execution_method", "direct") # How to actually run
        mitre_id = "T1564.009" # System Hiding: Argument Spoofing
        mitre_name = "Hide Artifacts: Argument Spoofing"
        result_details = {}

        if not original_command or not spoofed_command:
            return {"status": "error", "reason": "Missing 'command' or 'spoofed_command' in details.", "mitre_technique_id": mitre_id, "mitre_technique_name": mitre_name}

        self.logger.info(f"Attempting Argument Spoofing: Spoofed='{spoofed_command}', Actual='{original_command}'")
        result_details["original_command"] = original_command
        result_details["spoofed_command_logged"] = spoofed_command # Log what it *should* look like
        result_details["actual_command_executed"] = original_command

        # --- Simulation Logic ---
        # In a real scenario, this would involve complex process manipulation (e.g., modifying PEB).
        # Here, we simulate by: 
        # 1. Executing the *original* command.
        # 2. Returning a result that *claims* the spoofed command was run.
        self.logger.warning("Argument Spoofing is SIMULATED. Executing the original command but logging the spoofed one.")
        
        try:
            # Execute the *actual* command using the chosen method
            exec_result = self._execute_command(original_command, method=execution_method, capture=True)
            
            result_details["execution_result"] = exec_result # Include actual execution details for debugging/info
            
            # Report success/failure based on the *actual* execution
            status = exec_result.get("status", "failure")
            if status != "success":
                 result_details["reason"] = exec_result.get("reason", "Actual command execution failed.")
                 self.logger.error(f"Argument Spoofing simulation failed because underlying command failed: {result_details['reason']}")
            else:
                 self.logger.info("Argument Spoofing simulation completed (actual command ran successfully). Logging spoofed command.")

        except Exception as e:
            reason = f"Unexpected error during argument spoofing simulation: {e}"
            result_details["reason"] = reason
            self.logger.error(reason, exc_info=True)
            status = "error"

        return {
            "status": status, # Reflects success/failure of *actual* command
            "technique": "argument_spoofing",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "simulation_note": "Executed original command, logged spoofed command.",
            "details": result_details
        }

    # --- OS-Specific Dispatchers (Examples) ---

    def _handle_pid_spoofing(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch PID Spoofing to the OS-specific handler."""
        if self.os_handler and "pid_spoofing" in self.os_handler.handler_map:
             return self.os_handler.evade("pid_spoofing", details)
        else:
             logger.warning(f"PID Spoofing is not supported on {self.os_type}.")
             return {"status": "not_implemented", "reason": f"PID Spoofing not supported on {self.os_type}", "technique": "pid_spoofing"}
             
    # --- Placeholder Handlers ---

    def _handle_process_evasion(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Placeholder for generic process evasion techniques (e.g., hollowing)."""
        self.logger.warning("Process Evasion technique is not implemented.")
        return {"status": "not_implemented", "reason": "Process Evasion handler not implemented", "technique": "process_evasion"}

    def _handle_network_evasion(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Placeholder for generic network evasion techniques (e.g., traffic manipulation)."""
        self.logger.warning("Network Evasion technique is not implemented.")
        return {"status": "not_implemented", "reason": "Network Evasion handler not implemented", "technique": "network_evasion"}

    def _log_error(self, message: str, exc_info=False) -> None:
        """Log errors using the initialized logger."""
        logger.error(message, exc_info=exc_info)

# Example Usage (within BlueFireNexus execute_operation):
# defense_evasion_module = DefenseEvasion(execution_module_instance)
# operation_data = {
#     "technique": "pid_spoofing", # or "file_evasion", "argument_spoofing"
#     "details": { ... }
# }
# result = defense_evasion_module.run_evasion(operation_data)

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
    evasion_module = DefenseEvasion(execution_module=mock_exec)
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