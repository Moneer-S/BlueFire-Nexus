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

# Import the OS-specific handlers
from .windows_persistence import WindowsPersistence
from .linux_persistence import LinuxPersistence
# Import macOS handler when created
from .macos_persistence import MacOSPersistence

# Import the Execution module interface (adjust path as necessary)
from ..execution.execution import Execution

logger = logging.getLogger(__name__)

class Persistence:
    """Manages persistence operations by dispatching to OS-specific handlers."""

    def __init__(self, execution_module: Execution):
        """
        Initializes the Persistence module.

        Args:
            execution_module (Execution): An instance of the Execution module
                                         for running commands.
        """
        self.execution = execution_module
        self.os_type = platform.system()
        self.os_handler = None

        # The _execute_command helper passed to OS handlers
        # This ensures OS handlers use the main Execution module
        def _execute_command_wrapper(command: str, capture_output: bool = False) -> Dict[str, Any]:
            try:
                result = self.execution.execute_command(command, capture_output=capture_output)
                # Ensure result is a dict, adapt if execute_command returns differently
                if isinstance(result, dict):
                     return result
                else:
                     # Adapt based on actual return type of execute_command
                     logger.warning(f"Unexpected return type from execute_command: {type(result)}. Adapting.")
                     return {"status": "unknown", "output": str(result), "error": "", "return_code": -1}
            except Exception as e:
                 logger.error(f"Error executing command via Execution module: {e}", exc_info=True)
                 return {"status": "failure", "reason": str(e), "return_code": -1}

        # Instantiate the appropriate OS handler
        if self.os_type == "Windows":
            self.os_handler = WindowsPersistence(execute_command_func=_execute_command_wrapper)
            logger.info("Initialized Windows Persistence handler.")
        elif self.os_type == "Linux":
            self.os_handler = LinuxPersistence(execute_command_func=_execute_command_wrapper)
            logger.info("Initialized Linux Persistence handler.")
        elif self.os_type == "Darwin": # macOS
            self.os_handler = MacOSPersistence(execute_command_func=_execute_command_wrapper)
            logger.info("Initialized macOS Persistence handler (implement techniques later).")
        else:
            logger.error(f"Unsupported OS for Persistence module: {self.os_type}")
            self.os_handler = None

        # Define supported techniques based on the loaded handler
        self.supported_techniques = list(self.os_handler.handler_map.keys()) if self.os_handler else []
        # Add general simulation techniques here
        self.general_sim_techniques = {
            "boot_logon_autostart_sim": self._handle_boot_logon_autostart_sim
        }
        self.supported_techniques.extend(self.general_sim_techniques.keys())
        self.supported_techniques = sorted(list(set(self.supported_techniques))) # Ensure unique and sorted

        logger.info(f"Supported persistence techniques on {self.os_type}: {self.supported_techniques}")

    def update_config(self, config: Dict[str, Any]):
        """Update internal config with loaded configuration."""
        # This method is now empty as the configuration is managed by the OS-specific handlers

    def establish_persistence(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Establishes persistence based on the provided technique and details.
        Delegates to the OS-specific handler.

        Args:
            data (Dict[str, Any]): Dictionary containing persistence details.
                                     Expected format: {
                                         "technique": "technique_name",
                                         "details": { ... technique specific details ... }
                                     }

        Returns:
            Dict[str, Any]: Result dictionary indicating status and details.
        """
        technique = data.get("technique")
        details = data.get("details", {})

        if not technique:
            return {"status": "failure", "reason": "Missing 'technique' in operation data."}

        if not self.os_handler:
            logger.error(f"Persistence handler not available for OS: {self.os_type}")
            return {"status": "failure", "technique": technique, "reason": f"Persistence not supported on {self.os_type}"}

        # Check OS-specific handlers first
        if technique in self.os_handler.handler_map:
            logger.info(f"Attempting OS-specific persistence via '{technique}' on {self.os_type}")
            try:
                result = self.os_handler.establish(technique, details)
                return result
            except Exception as e:
                logger.error(f"OS-specific handler error for '{technique}': {e}", exc_info=True)
                return {"status": "failure", "technique": technique, "reason": f"Internal OS handler error: {str(e)}"}
        # Check general simulation handlers
        elif technique in self.general_sim_techniques:
            logger.info(f"Attempting general simulation persistence via '{technique}'")
            try:
                handler = self.general_sim_techniques[technique]
                result = handler(details) # Pass details directly
                return result
            except Exception as e:
                 logger.error(f"General simulation handler error for '{technique}': {e}", exc_info=True)
                 return {"status": "failure", "technique": technique, "reason": f"Internal simulation handler error: {str(e)}"}
        else:
             logger.warning(f"Technique '{technique}' is not supported by the {self.os_type} handler or general simulations.")
             return {"status": "failure", "technique": technique, "reason": f"Technique '{technique}' not supported on {self.os_type}"}

    def _handle_boot_logon_autostart_sim(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Simulates various boot/logon autostart persistence methods."""
        command = details.get("command")
        payload_path = details.get("payload_path") # Path to payload if command runs a file
        method_type = details.get("method_type", "unknown") # e.g., registry, startup_folder, plist, cron_reboot, systemd
        scope = details.get("scope", "user") # user | system
        name = details.get("name", "BlueFireAutostart") # Name for registry key, filename, service name etc.

        mitre_id = "T1547"
        mitre_name = "Boot or Logon Autostart Execution"

        if not command and not payload_path:
             return {"status": "error", "technique": "boot_logon_autostart_sim", "reason": "Missing 'command' or 'payload_path' detail.", "mitre_id": mitre_id}
        
        status = "success"
        reason = f"Simulation: Logged intent to establish {scope}-level persistence via {method_type}."
        
        log_msg = f"Simulating Boot/Logon Autostart Persistence:"
        log_msg += f"\n  Method Type: {method_type}"
        log_msg += f"\n  Scope: {scope}"
        log_msg += f"\n  Name/Identifier: {name}"
        if command: log_msg += f"\n  Command: {command}"
        if payload_path: log_msg += f"\n  Payload Path: {payload_path}"
        logger.info(log_msg)
        
        # In a real implementation, this would delegate to OS-specific code
        # based on method_type (e.g., call _handle_registry_run_key, _handle_startup_folder, etc.)

        return {
            "status": status,
            "technique": "boot_logon_autostart_sim",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": {
                 "method_type": method_type,
                 "scope": scope,
                 "name": name,
                 "command_simulated": command,
                 "payload_path_simulated": payload_path,
                 "message": reason
            },
            "reason": None # Success is just logging
        }

    def _handle_not_implemented(self, details: Dict[str, Any], technique_name: str) -> Dict[str, Any]:
        """Placeholder for techniques not yet implemented."""
        logger.warning(f"Persistence technique '{technique_name}' is not implemented.")
        return {"status": "not_implemented", "technique": technique_name, "reason": "Handler not implemented."}

    def _log_error(self, message: str, exc_info=False) -> None:
        """Log errors using the initialized logger."""
        logger.error(message, exc_info=exc_info)
        
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