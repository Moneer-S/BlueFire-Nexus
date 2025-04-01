"""
Execution Module
Handles command and payload execution.
"""

import subprocess
import platform
import os
import base64
import tempfile
import logging
import re # For caret obfuscation
import stat # For chmod
import uuid
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime
import shlex

# Import OS-specific handlers
from .windows_execution import WindowsExecution
from .linux_execution import LinuxExecution
from .macos_execution import MacOSExecution

logger = logging.getLogger(__name__)

class Execution:
    """Handles command and payload execution by dispatching to OS-specific handlers."""

    def __init__(self):
        self.os_type = platform.system()
        self.os_handler = None
        self.config = { # General config (can be overridden by OS handler config)
            "execution_timeout": 120,
        }

        # Instantiate the appropriate OS handler
        if self.os_type == "Windows":
            self.os_handler = WindowsExecution()
        elif self.os_type == "Linux":
            self.os_handler = LinuxExecution()
        elif self.os_type == "Darwin":
            self.os_handler = MacOSExecution()
        else:
            logger.error(f"Unsupported OS for Execution module: {self.os_type}")
            # Provide a fallback handler?
            self.os_handler = None # Or a generic handler that fails

        if self.os_handler:
             logger.info(f"Initialized {self.os_type} Execution handler.")
             # Update general config with OS handler defaults if needed
             self.config.update(self.os_handler.config)
        else:
             logger.error(f"Could not initialize execution handler for OS: {self.os_type}")

    def update_config(self, config: Dict[str, Any]):
        """Update general config and delegate to OS handler config."""
        exec_config = config.get("execution", {})
        self.config.update(exec_config)
        if self.os_handler and hasattr(self.os_handler, 'update_config'):
             self.os_handler.update_config(exec_config) # Pass relevant part
        logger.info("Execution module configuration updated.")

    def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Route execution requests (command or payload) to the OS handler."""
        results = {}
        errors = []
        overall_status = "failure" # Default if no handler or all fail

        if not self.os_handler:
             return {"status": "failure", "reason": f"Execution handler not available for OS: {self.os_type}"}

        execution_requests = data.get("execute", {})

        # Determine execution type (command or payload) and dispatch
        exec_type = None
        details = None
        if "command" in execution_requests:
            exec_type = "command"
            details = execution_requests["command"] if isinstance(execution_requests["command"], dict) else {}
            if not details.get("cmd"):
                errors.append("Command execution requested but 'cmd' field is missing.")
                details = None # Prevent execution
        elif "payload" in execution_requests:
            exec_type = "payload"
            details = execution_requests["payload"] if isinstance(execution_requests["payload"], dict) else {}
            if not details.get("content_b64") or not details.get("method"):
                errors.append("Payload execution requested but 'content_b64' or 'method' is missing.")
                details = None # Prevent execution

        if exec_type and details:
            try:
                # Delegate to the OS handler's execute method
                exec_result = self.os_handler.execute(exec_type, details)
                results[exec_type] = exec_result
                if exec_result.get("status") != "success":
                     errors.append(exec_result.get("reason", f"{exec_type.capitalize()} execution failed"))
            except Exception as e:
                error_msg = f"Execution dispatch for '{exec_type}' failed: {e}"
                errors.append(error_msg)
                self._log_error(error_msg, exc_info=True)
                results[exec_type] = {"status": "failure", "reason": error_msg}
        elif not errors: # Only add this error if no other validation error occurred
             errors.append("No valid 'command' or 'payload' execution request found in 'execute' data.")

        # Determine overall status
        if results and any(res.get("status") == "success" for res in results.values()):
            overall_status = "partial_success" if errors else "success"
        elif errors: # No successes, and errors occurred
             overall_status = "failure"
        else: # No results and no errors likely means no valid request
            overall_status = "failure" 
            if not errors: errors.append("No operation performed.") # Add error if none existed

        return {
            "status": overall_status,
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "errors": errors if errors else None
        }

    # Convenience method for direct command execution (used by other modules)
    def execute_command(self, command: str, capture_output: bool = True, method: str = "direct") -> Dict[str, Any]:
        """Provides a simple interface for running a command via the OS handler."""
        self.logger.debug(f"Executing direct command request: '{command}'")
        if not self.os_handler:
            return {"status": "failure", "reason": f"Execution handler not available for OS: {self.os_type}"}
        
        command_details = {
             "cmd": command,
             "method": method,
             "capture_output": capture_output
        }
        
        try:
             # Directly call the OS handler's command execution method if possible
             if hasattr(self.os_handler, '_handle_command_execution'):
                  # Note: This bypasses the OS handler's main 'execute' dispatch logic,
                  #       use with care or route through self.execute instead.
                  return self.os_handler._handle_command_execution(command_details)
             else:
                  # Fallback to routing through the main execute method
                  request_data = {"execute": {"command": command_details}}
                  result_wrapper = self.execute(request_data)
                  return result_wrapper.get("results", {}).get("command", {})
        except Exception as e:
            error_msg = f"Direct command execution failed: {e}"
            self._log_error(error_msg, exc_info=True)
            return {"status": "failure", "reason": error_msg}

    def _log_error(self, message: str, exc_info=False) -> None:
        """Log errors using the initialized logger."""
        logger.error(message, exc_info=exc_info)

# Example Usage (for testing)
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    execution_module = Execution()
    # execution_module.update_config({}) # Load actual config here if needed
    
    print("\n--- Testing Command Execution (Direct) ---")
    cmd_request_direct = {"execute": {"command": {"cmd": "whoami"}}}
    cmd_result_direct = execution_module.execute(cmd_request_direct)
    import json
    print(json.dumps(cmd_result_direct, indent=2))

    print("\n--- Testing Command Execution (PowerShell - Windows) ---")
    if platform.system() == "Windows":
        cmd_request_ps = {"execute": {"command": {"cmd": "Get-Process | Select-Object -First 3 Name, Id", "method": "powershell"}}}
        cmd_result_ps = execution_module.execute(cmd_request_ps)
        print(json.dumps(cmd_result_ps, indent=2))
    else:
        print("Skipping PowerShell test (not Windows)")

    print("\n--- Testing Command Execution (Bash - Non-Windows) ---")
    if platform.system() != "Windows":
        cmd_request_bash = {"execute": {"command": {"cmd": "echo 'Hello from Bash' && ls -la | head -n 5", "method": "bash"}}}
        cmd_result_bash = execution_module.execute(cmd_request_bash)
        print(json.dumps(cmd_result_bash, indent=2))
    else:
        print("Skipping Bash test (is Windows)")
        
    print("\n--- Testing Command Execution (Failure) ---")
    cmd_request_fail = {"execute": {"command": {"cmd": "nonexistent_command_12345", "method": "direct"}}}
    cmd_result_fail = execution_module.execute(cmd_request_fail)
    print(json.dumps(cmd_result_fail, indent=2))

    print("\n--- Testing Command Execution (PowerShell Base64 Obfuscation) ---")
    if platform.system() == "Windows":
        cmd_request_ps_b64 = {"execute": {"command": {"cmd": "Write-Host 'Hello from Base64 PS!'; $env:USERNAME", "method": "powershell", "obfuscation": "base64"}}}
        cmd_result_ps_b64 = execution_module.execute(cmd_request_ps_b64)
        print(json.dumps(cmd_result_ps_b64, indent=2))
    else:
        print("Skipping PowerShell Base64 test (not Windows)")

    print("\n--- Testing Command Execution (CMD Caret Obfuscation) ---")
    if platform.system() == "Windows":
        # Simple command that uses special chars
        cmd_request_caret = {"execute": {"command": {"cmd": "echo Hello & echo World | findstr World", "method": "cmd", "obfuscation": "caret"}}}
        cmd_result_caret = execution_module.execute(cmd_request_caret)
        print(json.dumps(cmd_result_caret, indent=2))
    else:
        print("Skipping CMD Caret test (not Windows)")

    print("\n--- Testing Command Execution (String Concat Obfuscation - Bash) ---")
    if platform.system() != "Windows":
        cmd_request_concat = {"execute": {"command": {"cmd": "whoami", "method": "bash", "obfuscation": "string_concat"}}}
        cmd_result_concat = execution_module.execute(cmd_request_concat)
        print(json.dumps(cmd_result_concat, indent=2))
    else:
        print("Skipping String Concat Bash test (is Windows)") 