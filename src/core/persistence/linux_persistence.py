import os
import platform
import subprocess
import shlex # Import shlex for robust shell argument quoting
from typing import Dict, Any, Tuple, Optional, List
import logging
from pathlib import Path # Use pathlib for cleaner path handling
import uuid
import pwd
import re
import shutil
from datetime import datetime

# Assume logger is passed or configured appropriately
logger = logging.getLogger(__name__)

class LinuxPersistence:
    """Handles Linux-specific persistence techniques."""

    def __init__(self, execute_command_func):
        """
        Initialize LinuxPersistence.

        Args:
            execute_command_func: A callable provided by the main Persistence class
                                  to execute commands.
        """
        self._execute_command = execute_command_func
        self.handler_map = {
            "cron_job": self._handle_cron_job,
            "profile_script": self._handle_profile_script,
            "systemd_unit": self._handle_systemd_unit,
            # Add other Linux techniques here (e.g., bashrc)
        }

    def establish(self, technique: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Establish persistence using a specific Linux technique."""
        handler = self.handler_map.get(technique)
        if handler:
            logger.info(f"Executing Linux persistence technique: {technique}")
            try:
                return handler(details)
            except Exception as e:
                logger.error(f"Error executing Linux persistence technique '{technique}': {e}", exc_info=True)
                return {"status": "failure", "technique": technique, "reason": str(e)}
        else:
            logger.warning(f"Unsupported Linux persistence technique requested: {technique}")
            return {"status": "failure", "technique": technique, "reason": "Unsupported technique for Linux/macOS"}

    # --- Technique Handlers ---

    def _handle_cron_job(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Add or remove cron jobs (Linux/macOS) using crontab and a comment marker."""
        action = details.get("action", "add").lower() # add | remove
        command = details.get("command")
        schedule = details.get("schedule", "@reboot") # e.g., @reboot, @hourly, */5 * * * *
        # Comment is crucial for reliable removal and idempotency
        comment = details.get("comment", f"BlueFire_Marker_{uuid.uuid4().hex[:6]}") 

        mitre_id = "T1053.003"
        mitre_name = "Scheduled Task/Job: Cron"

        if action not in ["add", "remove"]:
            return {"status": "failure", "technique": "cron_job", "reason": f"Invalid action: {action}. Use 'add' or 'remove'.", "mitre_id": mitre_id}

        if action == "add" and not command:
            return {"status": "failure", "technique": "cron_job", "reason": "Missing 'command' detail for adding cron job.", "mitre_id": mitre_id}
        if not comment:
             # Require comment for reliable operation, especially removal
             return {"status": "failure", "technique": "cron_job", "reason": "Missing required 'comment' detail for cron job operation.", "mitre_id": mitre_id}

        logger.info(f"Attempting to {action} cron job using comment marker: '{comment}'")
        if action == "add": logger.debug(f"Cron Command: {command} | Schedule: {schedule}")

        # Define the marker and the line to add (only used for 'add')
        check_marker = f"# {comment}"
        cron_line_to_add = f"{check_marker}\n{schedule} {command}"

        # Quote marker and line safely for shell embedding
        quoted_check_marker = shlex.quote(check_marker)
        quoted_cron_line_to_add = shlex.quote(cron_line_to_add)

        command_to_run = ""
        verification_expectation = False # False = marker should NOT exist after remove, True = marker SHOULD exist after add

        if action == "add":
            verification_expectation = True
            # Command logic: Check if marker exists; if not, get current crontab, add line, install.
            command_to_run = (
            f"crontab -l 2>/dev/null | grep -Fxq {quoted_check_marker} || "
                f"( (crontab -l 2>/dev/null ; echo -e {quoted_cron_line_to_add}) | crontab - )"
            )
            success_log_msg = "Cron job add/check command executed (either already present or added)."
            fail_reason_prefix = "Failed to execute cron job add/check command."
            verify_fail_reason = f"Cron job add/check command succeeded, but final verification failed. Marker '{comment}' not found after add attempt."
            verify_success_log_msg = f"Cron job ADD verified successfully in crontab using marker: '{comment}'."

        elif action == "remove":
            verification_expectation = False
            # Command logic: Get current crontab, filter *out* the marker line, install the result.
            # Using grep -Fv to exclude the fixed string marker.
            command_to_run = (
                f"( crontab -l 2>/dev/null | grep -Fxv {quoted_check_marker} ) | crontab -"
            )
            success_log_msg = "Cron job removal command executed."
            fail_reason_prefix = "Failed to execute cron job removal command."
            verify_fail_reason = f"Cron job removal command succeeded, but final verification failed. Marker '{comment}' still found after removal attempt."
            verify_success_log_msg = f"Cron job REMOVAL verified successfully (marker '{comment}' is absent)."

        status = "failure"
        reason = ""
        verification_passed = False
        exec_details = {}

        try:
            logger.debug(f"Executing crontab modification command: {command_to_run}")
            exec_result_modify = self._execute_command(command_to_run, capture_output=True)
            
            exec_details = {
                "command_executed": command_to_run,
                "output": exec_result_modify.get('output', ''),
                "error": exec_result_modify.get('error', ''),
                "return_code": exec_result_modify.get('return_code')
            }

            # Check the result of the modification command.
            # RC=0 is generally expected for success in both add and remove filtering/piping.
            if exec_result_modify.get('return_code') == 0:
                logger.info(success_log_msg)
                # Now, explicitly verify the state of the marker.
                verify_cmd = f"crontab -l 2>/dev/null | grep -Fxq {quoted_check_marker}"
                logger.debug(f"Verifying cron job state with command: {verify_cmd}")
                exec_result_verify = self._execute_command(verify_cmd, capture_output=True)
                
                marker_found = (exec_result_verify.get('return_code') == 0)
                
                if marker_found == verification_expectation:
                    logger.info(verify_success_log_msg)
                    status = "success"
                    verification_passed = True
                else:
                    reason = verify_fail_reason
                    logger.error(reason)
            else:
                output = exec_details.get('output', '')
                error_msg = exec_details.get('error', '')
                reason = f"{fail_reason_prefix} RC: {exec_details.get('return_code')}. Error: {error_msg or output}"
                logger.error(reason)

        except Exception as e:
            logger.error(f"Exception during cron job {action}: {e}", exc_info=True)
            reason = f"Exception: {e}"
            exec_details["internal_error"] = reason

        # Prepare result details, hiding command if removing
        result_details_payload = {
            "action": action,
            "schedule": schedule if action == "add" else None,
            "command": command if action == "add" else None,
            "comment_marker": comment,
            "verification_passed": verification_passed,
            "execution_details": exec_details
        }

        return {
            "status": status,
            "technique": "cron_job",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(), # Add timestamp
            "details": result_details_payload,
            "reason": reason if status != "success" else None
        }

    def _find_profile_scripts(self) -> List[Path]:
        """Find common user profile scripts that exist."""
        home_dir = Path.home()
        common_scripts = [
            ".bashrc",
            ".bash_profile",
            ".zshrc",
            ".zprofile",
            ".profile" # Often sourced by others
        ]
        existing_scripts = []
        for script_name in common_scripts:
            script_path = home_dir / script_name
            if script_path.is_file():
                logger.debug(f"Found profile script: {script_path}")
                existing_scripts.append(script_path)
            else:
                 logger.debug(f"Profile script not found: {script_path}")
        # Add logic here to potentially detect default shell and prioritize its script?
        # e.g., using `os.environ.get('SHELL')`
        return existing_scripts

    def _handle_profile_script(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Add or remove a command block in user profile scripts using markers."""
        # Parameters:
        # - action: "add" (default) or "remove".
        # - command: The shell command line to add (required for action="add").
        # - comment: A unique comment marker for identification/removal (required).
        # - target_scripts: Optional list of script filenames (e.g., [".bashrc"]). 
        #                   If None, attempts to find and modify common ones.

        action = details.get("action", "add").lower()
        command = details.get("command")
        # Require a comment for reliable operation
        comment = details.get("comment") 
        target_scripts_names = details.get("target_scripts") # Optional specific list

        mitre_id = "T1546.004"
        mitre_name = "Event Triggered Execution: Unix Shell Configuration Modification"

        if action not in ["add", "remove"]:
            return {"status": "failure", "technique": "profile_script", "reason": f"Invalid action: {action}. Use 'add' or 'remove'.", "mitre_id": mitre_id}
        if not comment:
             return {"status": "failure", "technique": "profile_script", "reason": "Missing required 'comment' detail for identification.", "mitre_id": mitre_id}
        if action == "add" and not command:
            return {"status": "failure", "technique": "profile_script", "reason": "Missing 'command' detail for adding to profile script.", "mitre_id": mitre_id}

        logger.info(f"Attempting to {action} command block in profile script(s). Marker: '{comment}'")
        if action == "add": logger.debug(f"Profile Script Command: {command}")

        start_marker = f"# --- {comment} ---"
        end_marker = f"# --- End {comment} ---"
        block_to_add = f"\n{start_marker}\n{command}\n{end_marker}\n"

        # Determine which scripts to modify
        scripts_to_process: List[Path] = []
        if target_scripts_names:
            home_dir = Path.home()
            for name in target_scripts_names:
                 script_path = home_dir / name
                 if script_path.is_file():
                      scripts_to_process.append(script_path)
                 else:
                      logger.warning(f"Specified target script '{name}' not found at {script_path}. Skipping.")
        else:
            scripts_to_process = self._find_profile_scripts()

        if not scripts_to_process:
             return {"status": "failure", "technique": "profile_script", "reason": "No suitable profile scripts found to process.", "mitre_id": mitre_id}

        overall_status = "failure" # Default status
        operation_results = {}

        for script_path in scripts_to_process:
             file_path_str = str(script_path)
             logger.debug(f"Processing script: {file_path_str} for action: {action}")
             file_status = "failure"
             file_reason = ""
             verification_passed = False

             try:
                 original_content = script_path.read_text(encoding='utf-8', errors='ignore')
                 marker_present = start_marker in original_content
                 new_content = ""

                 if action == "add":
                     if marker_present:
                         file_reason = f"Marker '{comment}' already found. Skipping add."
                         logger.info(f"[{file_path_str}] {file_reason}")
                         file_status = "skipped" # Idempotency - already present
                         verification_passed = True # It's already there
                     else:
                         # Append the block
                         new_content = original_content + block_to_add
                         script_path.write_text(new_content, encoding='utf-8')
                         # Verify by re-reading
                         content_after_write = script_path.read_text(encoding='utf-8', errors='ignore')
                         if start_marker in content_after_write:
                             logger.info(f"[{file_path_str}] Successfully appended command block.")
                             file_status = "success"
                             verification_passed = True
                         else:
                             file_reason = "Command block appended, but start marker verification failed."
                             logger.error(f"[{file_path_str}] {file_reason}")
                 
                 elif action == "remove":
                     if not marker_present:
                         file_reason = f"Marker '{comment}' not found. Cannot remove."
                         logger.warning(f"[{file_path_str}] {file_reason}")
                         file_status = "skipped" # Cannot remove what isn't there
                         verification_passed = True # It's already absent
                     else:
                         # Filter out the block
                         lines = original_content.splitlines()
                         filtered_lines = []
                         in_block = False
                         for line in lines:
                             if line.strip() == start_marker:
                                 in_block = True
                                 continue # Skip start marker
                             if line.strip() == end_marker:
                                 in_block = False
                                 continue # Skip end marker
                             if not in_block:
                                 filtered_lines.append(line)
                         
                         new_content = "\n".join(filtered_lines)
                         # Add trailing newline if original had one and new one doesn't
                         if original_content.endswith('\n') and not new_content.endswith('\n'):
                             new_content += "\n"
                             
                         script_path.write_text(new_content, encoding='utf-8')
                         # Verify by re-reading
                         content_after_write = script_path.read_text(encoding='utf-8', errors='ignore')
                         if start_marker not in content_after_write:
                             logger.info(f"[{file_path_str}] Successfully removed command block.")
                             file_status = "success"
                             verification_passed = True
                  else:
                             file_reason = "Command block removed, but start marker verification failed (still found)."
                             logger.error(f"[{file_path_str}] {file_reason}")

             except PermissionError as e:
                  file_reason = f"Permission denied accessing/modifying: {e}"
                  logger.error(f"[{file_path_str}] {file_reason}")
             except Exception as e:
                  file_reason = f"Unexpected error processing: {e}"
                  logger.error(f"[{file_path_str}] {file_reason}", exc_info=True)
                  
             operation_results[file_path_str] = {
                  "status": file_status,
                  "reason": file_reason if file_status == "failure" else None,
                  "verification_passed": verification_passed
             }
             # Update overall status - success if at least one succeeded
             if file_status == "success":
                 overall_status = "success"
             # If not success yet, but skipped, consider it partial success for now
             elif file_status == "skipped" and overall_status != "success":
                 overall_status = "partial_success" # Or maybe "no_op"?

        # Determine final status based on individual results
        if all(res["status"] == "success" for res in operation_results.values()):
             final_report_status = "success"
        elif any(res["status"] == "success" for res in operation_results.values()):
             final_report_status = "partial_success"
        elif all(res["status"] == "skipped" for res in operation_results.values()):
             final_report_status = "skipped"
             overall_status = "skipped" # Override if all were skips
        else:
             final_report_status = "failure"
             overall_status = "failure"

        return {
            "status": overall_status, # High-level status
            "technique": "profile_script",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(), # Add timestamp
            "details": {
                 "action": action,
            "comment_marker": comment,
                 "command_processed": command if action == "add" else None,
                 "processed_files": operation_results,
                 "final_report_status": final_report_status # More granular status summary
            }
        }

    def _handle_systemd_unit(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Add or remove systemd user or system services."""
        action = details.get("action", "add").lower()
        service_name = details.get("service_name")
        command = details.get("command") # Required for add
        description = details.get("description", f"BlueFire Service ({service_name})")
        user_scope = details.get("user_scope", True) # Default to user service

        mitre_id = "T1543.002"
        mitre_name = "Create or Modify System Process: Systemd Service"

        # Input validation
        if not service_name:
            return {"status": "failure", "technique": "systemd_unit", "reason": "Missing required 'service_name' detail.", "mitre_id": mitre_id}
        # Ensure service name is safe for filenames and systemctl
        safe_service_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', service_name)
        if not safe_service_name.endswith(".service"):
            safe_service_name += ".service"
            logger.debug(f"Appended .service extension: {safe_service_name}")
        
        if action not in ["add", "remove"]:
            return {"status": "failure", "technique": "systemd_unit", "reason": f"Invalid action: {action}. Use 'add' or 'remove'.", "mitre_id": mitre_id}
        if action == "add" and not command:
             return {"status": "failure", "technique": "systemd_unit", "reason": "Missing required 'command' detail for adding service.", "mitre_id": mitre_id}

        # Determine target path and systemctl flags
        systemctl_flags = ""
        target_dir: Optional[Path] = None
        if user_scope:
            systemctl_flags = "--user"
            target_dir = Path.home() / ".config" / "systemd" / "user"
            scope_desc = "user"
        else:
            # System scope requires root privileges
            target_dir = Path("/etc/systemd/system")
            scope_desc = "system"
            logger.warning("Targeting system-wide systemd scope. Root privileges are required for subsequent systemctl commands.")

        unit_file_path = target_dir / safe_service_name

        logger.info(f"Attempting to {action} systemd {scope_desc} service: {safe_service_name}")

        status = "failure"
        reason = ""
        exec_log = [] # Store execution results

        def run_systemctl(systemctl_cmd: str) -> Tuple[bool, str]:
            full_cmd = f"systemctl {systemctl_flags} {systemctl_cmd}".strip()
            log_entry = {"command": full_cmd, "status": "failure", "output": "", "error": ""}
            try:
                logger.debug(f"Executing: {full_cmd}")
                result = self._execute_command(full_cmd, capture_output=True)
                log_entry["output"] = result.get('output', '')
                log_entry["error"] = result.get('error', '')
                rc = result.get("return_code")
                
                if rc == 0:
                    log_entry["status"] = "success"
                    logger.info(f"systemctl command successful: {systemctl_cmd}")
                    exec_log.append(log_entry)
                    return True, ""
                else:
                    err_msg = f"systemctl command failed (RC:{rc}): {systemctl_cmd}. Error: {log_entry['error'] or log_entry['output']}"
                    logger.error(err_msg)
                    log_entry["status"] = "failure"
                    log_entry["reason"] = err_msg
                    exec_log.append(log_entry)
                    return False, err_msg
            except Exception as e:
                 err_msg = f"Exception running systemctl command '{systemctl_cmd}': {e}"
                 logger.error(err_msg, exc_info=True)
                 log_entry["status"] = "exception"
                 log_entry["reason"] = err_msg
                 exec_log.append(log_entry)
                 return False, err_msg

        try:
            if action == "add":
                # Create target directory if it doesn't exist
                if not target_dir.exists():
                     logger.info(f"Creating target directory for {scope_desc} service: {target_dir}")
                     try:
                          target_dir.mkdir(parents=True, exist_ok=True)
                     except Exception as mkdir_err:
                          raise Exception(f"Failed to create target directory {target_dir}: {mkdir_err}")

                # Define unit file content
                wanted_by = "default.target" if user_scope else "multi-user.target"
                unit_content = f"""
[Unit]
Description={description}
After=network.target

[Service]
ExecStart={command}
Restart=on-failure
RestartSec=5s

[Install]
WantedBy={wanted_by}
"""
                logger.debug(f"Writing unit file to: {unit_file_path}")
                unit_file_path.write_text(unit_content, encoding='utf-8')

                # Reload daemon
                success, err = run_systemctl("daemon-reload")
                if not success:
                    raise Exception(f"Failed to reload systemd daemon: {err}")

                # Enable and start the service
                success, err = run_systemctl(f"enable --now {shlex.quote(safe_service_name)}")
                if not success:
                     raise Exception(f"Failed to enable/start service '{safe_service_name}': {err}")
                
                status = "success"
                logger.info(f"Systemd {scope_desc} service '{safe_service_name}' created and enabled successfully.")

            elif action == "remove":
                # Check if file exists before trying to remove
                if not unit_file_path.exists():
                    reason = f"Unit file {unit_file_path} does not exist. Assuming service is already removed or was never added."
                    logger.warning(reason)
                    status = "skipped" # Or success?
                else:
                    # Disable and stop the service
                    # Use --now to stop immediately. Ignore errors if service not found/loaded.
                    success, err = run_systemctl(f"disable --now {shlex.quote(safe_service_name)}")
                    if not success:
                        # Log warning but continue, maybe service wasn't running/enabled
                        logger.warning(f"Failed to disable/stop service '{safe_service_name}' (may already be stopped/disabled): {err}")
                        # Don't raise exception here, proceed to delete file
                    
                    # Delete the unit file
                    try:
                        logger.debug(f"Deleting unit file: {unit_file_path}")
                        unit_file_path.unlink()
                    except Exception as rm_err:
                         # If deletion fails, it's a bigger problem
                         raise Exception(f"Failed to delete unit file {unit_file_path}: {rm_err}")

                    # Reload daemon
                    success, err = run_systemctl("daemon-reload")
                    if not success:
                        raise Exception(f"Failed to reload systemd daemon after removal: {err}")
                    
                    status = "success"
                    logger.info(f"Systemd {scope_desc} service '{safe_service_name}' disabled and removed successfully.")

        except Exception as e:
            reason = f"Error during systemd operation ({action} {safe_service_name}): {e}"
            logger.error(reason, exc_info=True)
            status = "failure"

        return {
            "status": status,
            "technique": "systemd_unit",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": {
                "action": action,
                "service_name": safe_service_name,
                "scope": scope_desc,
                "unit_file_path": str(unit_file_path),
                "command_processed": command if action == "add" else None,
                "execution_log": exec_log
            },
            "reason": reason if status != "success" else None
        }

    # Add other Linux/macOS specific methods like _handle_bashrc etc. here 