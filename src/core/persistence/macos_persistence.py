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
            "launch_daemon": self._handle_launch_daemon,
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

    # --- Helper for Launch Agents/Daemons ---

    def _manage_launch_service(self, scope: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Core logic to add or remove macOS LaunchAgents or LaunchDaemons."""
        action = details.get("action", "add").lower()
        label = details.get("label") # Required
        command_str = details.get("command") # Required for add
        run_at_load = details.get("run_at_load", True)
        keep_alive = details.get("keep_alive", False)
        start_interval = details.get("start_interval")
        plist_name = details.get("plist_name")
        force = details.get("force", False)
        load_unload = details.get("load_unload", True) # Whether to run launchctl load/unload

        status = "failure" # Default
        reason = ""
        result_details = {}
        mitre_id = ""
        mitre_name = ""

        # --- Validate Inputs --- 
        if not label:
             return {"status": "failure", "reason": "Missing required parameter: 'label'.", "scope": scope}
        if action not in ["add", "remove"]:
             return {"status": "failure", "reason": f"Invalid action '{action}'. Must be 'add' or 'remove'.", "label": label, "scope": scope}
        if action == "add" and not command_str:
             return {"status": "failure", "reason": "Missing required parameter 'command' for add action.", "label": label, "scope": scope}

        # --- Determine Paths and Scope Settings --- 
        is_user_scope = (scope.lower() == 'user')
        launchctl_prefix = "" # No prefix for user launchctl
        target_dir: Optional[Path] = None

        if is_user_scope:
            mitre_id = "T1543.001"
            mitre_name = "Create or Modify System Process: LaunchAgent"
            target_dir = Path.home() / "Library" / "LaunchAgents"
        else: # System scope (Daemon)
            mitre_id = "T1543.004"
            mitre_name = "Create or Modify System Process: Launch Daemon"
            target_dir = Path("/Library/LaunchDaemons")
            # System scope requires root
            try:
                if os.geteuid() != 0:
                    return {"status": "failure_permissions", "reason": f"LaunchDaemon ({scope}) requires root privileges.", "label": label}
            except AttributeError:
                 return {"status": "failure", "reason": "Cannot verify privileges on this OS for system scope.", "label": label}
            # Note: launchctl for system daemons usually doesn't require sudo if run by root
            # launchctl_prefix = "sudo " # Might be needed if script isn't run as root

        if not plist_name:
            plist_name = f"{label}.plist"
        target_plist_path = target_dir / plist_name
        quoted_plist_path = shlex.quote(str(target_plist_path))

        logger.info(f"Attempting to {action} {scope} service '{label}' at {target_plist_path}")

        # Prepare result details common to add/remove
        result_details = {
            "action": action,
            "scope": scope,
            "label": label,
            "plist_path": str(target_plist_path),
            "command_processed": command_str if action == "add" else None,
            "launchctl_log": [] # Store results of launchctl calls
        }

        def run_launchctl(launchctl_args: str) -> Tuple[bool, str]:
            cmd = f"launchctl {launchctl_args}"
            log_entry = {"command": cmd, "status": "failure", "output": "", "error": ""}
            try:
                logger.debug(f"Executing: {cmd}")
                # Use -w for load/unload to write to overrides.plist (makes enable/disable sticky)
                result = self._execute_command(cmd, capture_output=True)
                log_entry["output"] = result.get('output', '')
                log_entry["error"] = result.get('error', '')
                rc = result.get("return_code")
                
                if rc == 0:
                    log_entry["status"] = "success"
                    logger.info(f"launchctl command successful: {launchctl_args}")
                    result_details["launchctl_log"].append(log_entry)
                    return True, ""
                else:
                    # Check for specific error patterns
                    err_out = log_entry['error'] or log_entry['output']
                    err_msg = f"launchctl command failed (RC:{rc}): {launchctl_args}. Error: {err_out}"
                    # Treat "service already loaded" / "not found" during unload as non-fatal for some cases
                    if "already loaded" in err_out and "load" in launchctl_args: 
                         log_entry["status"] = "skipped_already_loaded"
                         logger.warning(f"launchctl reports service '{label}' already loaded.")
                         result_details["launchctl_log"].append(log_entry)
                         return True, "Already loaded" # Treat as success for overall flow
                    elif ("Could not find specified service" in err_out or "No such file or directory" in err_out) and "unload" in launchctl_args:
                         log_entry["status"] = "skipped_not_found"
                         logger.warning(f"launchctl reports service '{label}' not found for unload.")
                         result_details["launchctl_log"].append(log_entry)
                         return True, "Not found" # Treat as success for removal flow
                    else:
                         logger.error(err_msg)
                         log_entry["status"] = "failure"
                         log_entry["reason"] = err_msg
                         result_details["launchctl_log"].append(log_entry)
                         return False, err_msg
            except Exception as e:
                 err_msg = f"Exception running launchctl command '{launchctl_args}': {e}"
                 logger.error(err_msg, exc_info=True)
                 log_entry["status"] = "exception"
                 log_entry["reason"] = err_msg
                 result_details["launchctl_log"].append(log_entry)
                 return False, err_msg

        # --- Execute Action --- 
        try:
            if action == "add":
                # Create directory if needed (user scope only for safety)
                if is_user_scope:
                     target_dir.mkdir(parents=True, exist_ok=True)
                elif not target_dir.exists():
                     # Root should have created /Library/LaunchDaemons
                     raise OSError(f"System LaunchDaemon directory not found: {target_dir}")

                # Check if file exists
                if target_plist_path.exists() and not force:
                    reason = f"Plist file '{target_plist_path}' already exists and force=False."
                    logger.warning(reason)
                    status = "skipped"
                else:
                    # Prepare plist content
                    try:
                        program_arguments = shlex.split(command_str)
                    except ValueError as e:
                        raise ValueError(f"Could not parse command string: {e}")
                    plist_data = {
                        "Label": label,
                        "ProgramArguments": program_arguments,
                        "RunAtLoad": run_at_load,
                        "KeepAlive": keep_alive,
                    }
                    if start_interval is not None:
                        try: plist_data["StartInterval"] = int(start_interval)
                        except ValueError: raise ValueError(f"Invalid start_interval: {start_interval}")
                    result_details["plist_generated"] = plist_data

                    # Write the plist file
                    logger.debug(f"Writing plist to {target_plist_path}")
                    with open(target_plist_path, 'wb') as fp:
                        plistlib.dump(plist_data, fp)
                    logger.info(f"Successfully wrote plist file.")
                    try: os.chmod(target_plist_path, 0o644) # Set permissions
                    except Exception as e_chmod: logger.warning(f"Could not chmod {target_plist_path}: {e_chmod}")

                    # Load the service if requested
                    if load_unload:
                        success, load_err = run_launchctl(f"load -w {quoted_plist_path}")
                        if not success and load_err != "Already loaded": 
                             # Raise exception if loading fails critically, otherwise just warn
                             raise Exception(f"Failed to load service '{label}': {load_err}")
                        elif not success:
                             reason = f"Plist created, but service '{label}' was already loaded."
                        else:
                             reason = f"Plist created and service '{label}' loaded successfully."
                    else:
                         reason = f"Plist created at {target_plist_path}. Loading skipped as requested."
                    
                    status = "success"

            elif action == "remove":
                plist_existed = target_plist_path.exists()

                # Unload the service first if requested and plist exists
                unload_success = True
                unload_msg = ""
                if load_unload and plist_existed:
                     unload_success, unload_msg = run_launchctl(f"unload -w {quoted_plist_path}")
                     if not unload_success and unload_msg != "Not found":
                          # Treat unload failure as warning, but proceed to delete file if possible
                          logger.warning(f"Failed to unload service '{label}' before removal: {unload_msg}. Attempting file deletion anyway.")
                          # Do not set status to failure here, file deletion is the primary goal
                elif not plist_existed:
                     logger.warning(f"Plist file '{target_plist_path}' not found for removal. Assuming already removed.")
                     status = "skipped"
                     reason = f"Plist file not found."

                # Delete the plist file if it exists
                if status != "skipped": # Only delete if we didn't skip due to file not found
                    if plist_existed:
                        logger.debug(f"Deleting plist file: {target_plist_path}")
                        target_plist_path.unlink()
                        if not target_plist_path.exists():
                             logger.info(f"Successfully deleted plist file: {target_plist_path}")
                             status = "success"
                             reason = f"Service '{label}' unloaded (if applicable) and plist file deleted."
                        else:
                             raise Exception(f"Plist file deletion failed: {target_plist_path}")
                    else: # Should have been caught earlier, but double-check
                         status = "skipped"
                         reason = "Plist file did not exist, nothing to remove."

        except Exception as e:
             error_reason = f"Error during {action} operation for {scope} service '{label}': {e}"
             logger.error(error_reason, exc_info=True)
             status = "failure"
             reason = error_reason

        result_details["final_reason"] = reason # Add final summary reason
        return {
            "status": status,
            "technique": f"launch_{scope}", # launch_agent or launch_daemon
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": result_details,
            "reason": reason if status != "success" else None
        }


    # --- Technique Handlers (Now thin wrappers) ---

    def _handle_launch_agent(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Establish or remove persistence using macOS LaunchAgents."""
        return self._manage_launch_service(scope="user", details=details)

    def _handle_launch_daemon(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Establish or remove persistence using macOS LaunchDaemons (Requires Root)."""
        return self._manage_launch_service(scope="system", details=details)

    # Add other macOS persistence handlers here...

    # --- Technique Handlers (Implement Later) ---

    # Example placeholder:
    # def _handle_launch_agent(self, details: Dict[str, Any]) -> Dict[str, Any]:
    #     logger.warning("LaunchAgent persistence technique not yet implemented.")
    #     return {"status": "not_implemented", "technique": "launch_agent", "reason": "Handler not implemented."} 