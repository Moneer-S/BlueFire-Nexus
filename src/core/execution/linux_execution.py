import subprocess
import platform
import os
import base64
import tempfile
import logging
import stat # For chmod
import uuid
import shlex
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class LinuxExecution:
    """Handles Linux/Unix-like specific command and payload execution."""

    def __init__(self):
        self.config = { # Default config values
            "execution_timeout": 120,
            "default_shell": "bash"
        }
        self.handler_map = {
            "command": self._handle_command_execution,
            "payload": self._handle_payload_execution,
        }
        logger.info("Linux/Unix Execution handler initialized.")

    def update_config(self, config: Dict[str, Any]):
        """Update internal config specific to Linux execution."""
        self.config.update(config)

    def execute(self, exec_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific Linux/Unix command or payload technique."""
        handler = self.handler_map.get(exec_type)
        if handler:
            logger.info(f"Executing Linux/Unix {exec_type} request.")
            try:
                result = handler(details)
                result["timestamp"] = datetime.now().isoformat()
                return result
            except Exception as e:
                logger.error(f"Error executing Linux/Unix {exec_type}: {e}", exc_info=True)
                return {"status": "failure", "type": exec_type, "reason": str(e)}
        else:
            logger.warning(f"Unsupported Linux/Unix execution type requested: {exec_type}")
            return {"status": "failure", "type": exec_type, "reason": f"Unsupported execution type '{exec_type}' for Linux/Unix"}

    # --- Internal Helper ---
    def _run_command(self, command: str, shell: Optional[str], use_shell: bool, capture: bool = True) -> Tuple[int, str, str]:
        """Helper to run subprocess commands specifically for Linux/Unix."""
        timeout = self.config.get("execution_timeout", 120)
        effective_shell = shell or self.config.get("default_shell", "bash")

        cmd_list_or_str = command
        if use_shell:
            # Pass command string directly to shell -c
            cmd_list_or_str = [effective_shell, "-c", command]
            use_actual_shell_param = False # subprocess uses list[0] as executable
        else:
            # Use shlex.split for safer arg splitting if not using shell
            try:
                 cmd_list_or_str = shlex.split(command)
                 use_actual_shell_param = False # Pass list directly
            except ValueError as e:
                 logger.warning(f"Could not shlex.split command '{command}': {e}. Using basic split.")
                 cmd_list_or_str = command.split()
                 use_actual_shell_param = False

        logger.info(f"Executing Linux/Unix command (shell={effective_shell if use_shell else 'None'}, use_shell_param={use_actual_shell_param}): {cmd_list_or_str}")

        try:
            process = subprocess.run(cmd_list_or_str,
                                     capture_output=capture,
                                     text=True,
                                     check=False,
                                     timeout=timeout,
                                     encoding='utf-8',
                                     errors='ignore',
                                     shell=use_actual_shell_param # Typically False when passing list
                                     )

            self.logger.debug(f"Command finished. RC: {process.returncode}")
            stdout = process.stdout if process.stdout else ""
            stderr = process.stderr if process.stderr else ""
            return process.returncode, stdout, stderr
        except FileNotFoundError:
            cmd_executed = cmd_list_or_str[0] if isinstance(cmd_list_or_str, list) else command.split()[0]
            logger.error(f"Command or shell not found: {cmd_executed}")
            raise FileNotFoundError(f"Required command/shell '{cmd_executed}' not found.")
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout}s: {command}")
            raise TimeoutError(f"Command '{command}' timed out.")
        except Exception as e:
            logger.error(f"Unexpected error running command '{command}': {e}", exc_info=True)
            raise

    # --- Obfuscation Helper (Linux/Unix specific could be added) ---
    def _apply_obfuscation(self, command: str, method: str, obfuscation_type: Optional[str]) -> Tuple[str, Optional[str]]:
        """Applies Linux/Unix-relevant obfuscation techniques (Placeholder)."""
        if not obfuscation_type:
            return command, None

        logger.warning(f"Linux/Unix obfuscation type '{obfuscation_type}' requested but not implemented. Returning original command.")
        # Add Linux specific obfuscation later (e.g., hex encoding, command substitution)
        return command, None

    # --- Command Execution Handler ---
    def _handle_command_execution(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a Linux/Unix shell command."""
        original_command = data.get("cmd")
        method = data.get("method", "direct") # direct, bash
        obfuscation = data.get("obfuscation")
        use_system_shell = data.get("use_shell_api", True if method == "bash" else False) # Default based on method
        capture_output = data.get("capture_output", True)

        if not original_command:
             raise ValueError("Missing 'cmd' in command execution data.")

        command_to_run, applied_obfuscation = self._apply_obfuscation(original_command, method, obfuscation)

        shell_to_use = None
        final_command_arg = command_to_run

        if method == "bash":
             shell_to_use = "bash"
             use_system_shell = True # Use shell -c
        elif method == "direct":
             shell_to_use = None
             use_system_shell = False # Run directly
        else:
            logger.warning(f"Unknown Linux/Unix execution method '{method}', using direct.")
            shell_to_use = None
            use_system_shell = False

        details = {
            "original_command": original_command,
            "command_executed_arg": final_command_arg,
            "obfuscation_requested": obfuscation,
            "obfuscation_applied": applied_obfuscation,
            "execution_method": method,
            "used_system_shell_api": use_system_shell,
            "shell_invoked": shell_to_use,
            "captured_output": capture_output,
            "return_code": -1, "stdout": "", "stderr": ""
        }

        try:
            rc, stdout, stderr = self._run_command(
                final_command_arg,
                shell=shell_to_use,
                use_shell=use_system_shell,
                capture=capture_output
            )
            details["return_code"] = rc
            details["stdout"] = stdout
            details["stderr"] = stderr
            status = "success" if rc == 0 else "failure"
            reason = f"Command failed with return code {rc}." if status == "failure" else "Command executed successfully."

        except Exception as e:
            logger.error(f"_run_command failed for '{original_command}': {e}", exc_info=True)
            status = "failure"
            reason = f"Execution failed: {e}"
            details["stderr"] = reason

        return {
            "status": status,
            "reason": reason,
            "technique": "command_execution",
            "details": details
        }

    # --- Payload Execution Handler ---
    def _handle_payload_execution(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handles Linux/Unix payload execution."""
        content_b64 = data.get("content_b64")
        method = data.get("method") # disk, memory
        file_extension = data.get("file_extension", ".sh") # Default to shell script
        args = data.get("args", [])

        if not content_b64 or not method:
            return {"status": "failure", "reason": "Missing content_b64 or method for payload execution."}

        try:
            payload_bytes = base64.b64decode(content_b64)
        except Exception as e:
            return {"status": "failure", "reason": f"Base64 decode error: {e}"}

        status = "failure"
        reason = f"Method '{method}' not implemented or failed."
        result_details = {
            "execution_method": method,
            "payload_size_bytes": len(payload_bytes),
            "args_provided": args,
        }

        if method == "disk":
            temp_file_path = None
            try:
                # Use /tmp or another writable location
                temp_dir = "/tmp"
                # Ensure temp_dir exists and is writable?
                if not os.path.isdir(temp_dir) or not os.access(temp_dir, os.W_OK):
                     temp_dir = tempfile.gettempdir()
                     logger.warning(f"/tmp not available, using default temp dir: {temp_dir}")
                
                temp_file_name = f"bf_{uuid.uuid4().hex}{file_extension}"
                temp_file_path = os.path.join(temp_dir, temp_file_name)

                with open(temp_file_path, 'wb') as tmp_file:
                    tmp_file.write(payload_bytes)
                logger.info(f"Payload written to temporary file: {temp_file_path}")

                # Make executable
                try:
                    current_st = os.stat(temp_file_path)
                    os.chmod(temp_file_path, current_st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
                    logger.info(f"Made temporary file executable: {temp_file_path}")
                except Exception as e_chmod:
                     logger.warning(f"Failed to chmod temporary file {temp_file_path}: {e_chmod}. Execution might fail.")

                command_parts = [temp_file_path] + args
                command_str = " ".join(shlex.quote(part) for part in command_parts)

                # Execute directly, no shell
                return_code, stdout, stderr = self._run_command(command_str, shell=None, use_shell=False, capture=True)

                result_details["temp_file_path"] = temp_file_path
                result_details["command_executed"] = command_str
                result_details["return_code"] = return_code
                result_details["stdout"] = stdout
                result_details["stderr"] = stderr

                if return_code == 0:
                    status = "success"
                    reason = "Payload executed successfully from disk."
                else:
                    reason = f"Payload execution from disk failed. RC: {return_code}. Stderr: {stderr[:200]}..."

            except Exception as e:
                reason = f"Error during disk payload execution: {e}"
            finally:
                if temp_file_path and os.path.exists(temp_file_path):
                    try:
                        os.remove(temp_file_path)
                        logger.info(f"Cleaned up temporary payload file: {temp_file_path}")
                    except Exception as e_clean:
                        logger.warning(f"Failed to cleanup temporary file {temp_file_path}: {e_clean}")

        elif method == "memory":
            # Placeholder for Linux/Unix memory execution (e.g., memfd_create, LD_PRELOAD for shared libs)
            logger.warning(f"Linux/Unix payload execution method '{method}' is not implemented.")
            status = "not_implemented"
            reason = "Linux/Unix memory execution is not implemented."
            result_details["reason"] = reason

        else:
             reason = f"Unsupported payload execution method: {method}"
             status = "failure"

        return {
            "status": status,
            "reason": reason,
            "technique": f"payload_execution_{method}",
            "details": result_details
        } 