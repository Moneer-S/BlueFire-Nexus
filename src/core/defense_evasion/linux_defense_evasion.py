import os
import platform
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

class LinuxDefenseEvasion:
    """Handles Linux/Unix-like specific defense evasion techniques."""

    def __init__(self, execute_command_func):
        """
        Initialize LinuxDefenseEvasion.
        Args:
            execute_command_func: Callable to execute commands.
        """
        self._execute_command = execute_command_func
        self.handler_map = {
            "file_hide": self._hide_file, # Map specific sub-action
            # Add more Linux techniques here (e.g., LD_PRELOAD)
        }
        logger.info("Linux/Unix Defense Evasion handler initialized.")

    def evade(self, technique: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific Linux/Unix evasion technique."""
        handler = self.handler_map.get(technique)
        if handler:
            logger.info(f"Executing Linux/Unix evasion technique: {technique}")
            try:
                # Add standard fields to the result returned by handler
                result = handler(details)
                result["technique"] = technique # Ensure technique name is in result
                result["timestamp"] = datetime.now().isoformat()
                return result
            except Exception as e:
                logger.error(f"Error executing Linux/Unix evasion technique '{technique}': {e}", exc_info=True)
                return {"status": "failure", "technique": technique, "reason": str(e)}
        else:
            logger.warning(f"Unsupported Linux/Unix evasion technique requested: {technique}")
            return {"status": "failure", "technique": technique, "reason": f"Unsupported technique '{technique}' for Linux/Unix"}

    # --- Technique Handlers ---

    def _hide_file(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Hide a file by prepending a dot to its name."""
        target_file = details.get("target_file")
        if not target_file or not os.path.exists(target_file):
             return {"status": "error", "reason": f"Target file '{target_file}' not provided or does not exist."}

        result_details = {"target_file": target_file}
        status = "failure"
        mitre_id = "T1564.001"
        mitre_name = "Hide Artifacts: Hidden Files and Directories"

        try:
            self.logger.info(f"Attempting to hide file (Unix-like): {target_file}")
            file_path = Path(target_file)
            if file_path.name.startswith('.'):
                 status = "skipped"
                 result_details["reason"] = "File already appears hidden (starts with dot)."
                 self.logger.warning(result_details["reason"])
            else:
                hidden_path = file_path.parent / ('.' + file_path.name)
                try:
                    os.rename(target_file, hidden_path)
                    status = "success"
                    result_details["new_path"] = str(hidden_path)
                    self.logger.info(f"Successfully hid file by renaming to: {hidden_path}")
                except OSError as e:
                    reason = f"Failed to rename file for hiding: {e}"
                    result_details["reason"] = reason
                    self.logger.error(reason, exc_info=True)

        except Exception as e:
            reason = f"Unexpected error during file hiding: {e}"
            result_details["reason"] = reason
            self.logger.error(reason, exc_info=True)
            status = "error"

        return {
            "status": status,
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "details": result_details
        }

    # Add other Linux/Unix specific methods here 