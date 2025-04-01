"""
Execution Module
Handles command and payload execution.
"""

import subprocess
import platform
import os
import base64
import tempfile
import logging
import re # For caret obfuscation
from typing import Dict, Any, List, Tuple
from datetime import datetime

class Execution:
    """Handles command and payload execution techniques."""

    def __init__(self):
        self.config = {
            "execution_timeout": 120, # Default timeout for commands
            "default_shell": "cmd" if platform.system() == "Windows" else "bash"
        }
        self.logger = logging.getLogger(__name__)

    def update_config(self, config: Dict[str, Any]):
        """Update internal config with loaded configuration."""
        self.config.update(config.get("execution", {}))
        self.logger.info("Execution module configuration updated.")

    def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Route execution requests to appropriate handlers."""
        result = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "results": {}
        }
        errors = []

        execution_requests = data.get("execute", {}) # e.g., {"command": {"cmd": "whoami", "method": "direct", "obfuscation": "caret"}}

        if "command" in execution_requests:
            command_config = execution_requests["command"] if isinstance(execution_requests["command"], dict) else {}
            if not command_config.get("cmd"):
                 errors.append("Command execution requested but 'cmd' field is missing.")
            else:
                try:
                    result["results"]["command_execution"] = self._handle_command_execution(command_config)
                except Exception as e:
                    errors.append(f"Command Execution failed: {e}")
                    self._log_error(f"Command Execution failed: {e}", exc_info=True)
        
        # Add handlers for payload execution later (e.g., execute_assembly, execute_pe)
        # ...

        if errors:
            result["status"] = "partial_success" if result["results"] else "failure"
            result["errors"] = errors
            
        return result

    def _run_command(self, command: str, shell: str, use_shell: bool, capture: bool = True) -> Tuple[int, str, str]:
        """Helper to run subprocess commands with timeout, shell choice, and error handling."""
        timeout = self.config.get("execution_timeout", 120)
        self.logger.info(f"Executing command via {shell} (use_shell={use_shell}): {command}")
        
        cmd_list = [shell, "/c", command] if platform.system() == "Windows" and shell == "cmd" and use_shell else \
                   [shell, "-c", command] if platform.system() != "Windows" and shell == "bash" and use_shell else \
                   command.split() # Basic split if not using shell - might need shlex for complex commands
        
        # If not using shell=True, cmd_list should ideally be prepared more carefully (e.g., using shlex)
        # For simplicity here, direct commands assume simple space splitting.

        try:
            # Use shell=True ONLY when explicitly required and understood.
            # Generally safer to pass a list of args when shell=False.
            process = subprocess.run(cmd_list if not use_shell else command, 
                                     capture_output=capture, 
                                     text=True, 
                                     check=False, # Don't raise exception on non-zero exit code, handle it manually
                                     timeout=timeout, 
                                     encoding='utf-8', 
                                     errors='ignore',
                                     shell=use_shell) # Critical parameter
                                     
            self.logger.debug(f"Command finished. Return code: {process.returncode}")
            stdout = process.stdout if process.stdout else ""
            stderr = process.stderr if process.stderr else ""
            return process.returncode, stdout, stderr
        except FileNotFoundError:
            self.logger.error(f"Shell/Command not found: {cmd_list[0] if not use_shell else 'shell'}")
            raise FileNotFoundError(f"Required shell/command '{cmd_list[0] if not use_shell else command}' not found.")
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out after {timeout}s: {command}")
            raise TimeoutError(f"Command '{command}' timed out.")
        except Exception as e:
            self.logger.error(f"Unexpected error running command '{command}': {e}", exc_info=True)
            raise # Re-raise unexpected errors

    def _apply_obfuscation(self, command: str, method: str, obfuscation_type: Optional[str]) -> Tuple[str, Optional[str]]:
        """Applies the specified obfuscation technique to the command."""
        if not obfuscation_type:
            return command, None # No obfuscation applied

        obfuscated_command = command
        applied_obfuscation = None
        self.logger.info(f"Applying obfuscation type '{obfuscation_type}' for method '{method}'")

        if obfuscation_type == "base64":
            # Primarily for PowerShell's -EncodedCommand
            if method == "powershell":
                try:
                    # PowerShell expects UTF-16LE encoding for -EncodedCommand
                    encoded_cmd = base64.b64encode(command.encode('utf-16le')).decode('ascii')
                    obfuscated_command = encoded_cmd # The encoded string itself is the command data
                    applied_obfuscation = "base64_encoded_command"
                except Exception as e:
                    self.logger.warning(f"Base64 encoding for PowerShell failed: {e}. Using original command.")
            else:
                self.logger.warning("Base64 obfuscation requested but method is not PowerShell. Obfuscation may not be effective.")
                # Could still base64 encode the command and try to decode+execute on the target shell, 
                # but that requires specific shell syntax (e.g., base64 -d | bash)
                # For now, just warn and return original for non-powershell methods.
                pass 

        elif obfuscation_type == "caret":
            # Primarily for Windows CMD
            if method == "cmd" or (method == "direct" and platform.system() == "Windows"):
                 # Add ^ before special CMD characters: &, |, <, >, (, ), @, ^, %
                 # Be careful not to break existing quoted strings or complex logic
                 # This is a basic example and might need refinement
                 special_chars = r"([&|<>\\(\\)\\@\\^%])" 
                 # Use a simple regex to add carets - might not handle all edge cases perfectly
                 try:
                      obfuscated_command = re.sub(special_chars, r"^\\1", command)
                      # Double check: Don't add caret if already present (avoid ^^)
                      obfuscated_command = obfuscated_command.replace("^^", "^")
                      applied_obfuscation = "cmd_caret_escaping"
                 except Exception as e:
                      self.logger.warning(f"Caret obfuscation failed: {e}. Using original command.")
            else:
                 self.logger.warning("Caret obfuscation requested but method is not cmd/direct(Windows). Obfuscation skipped.")

        elif obfuscation_type == "string_concat":
            # Simple example for PowerShell or Bash - break command into parts
            if method in ["powershell", "bash"]:
                try:
                    parts = command.split() # Split command and args
                    obfuscated_parts = []
                    for part in parts:
                        if len(part) > 2: # Only obfuscate longer parts
                            # Simple split and join
                            split_point = random.randint(1, len(part) - 1)
                            p1 = part[:split_point]
                            p2 = part[split_point:]
                            if method == "powershell":
                                obfuscated_parts.append(f"('{p1}'+'{p2}')")
                            elif method == "bash":
                                obfuscated_parts.append(f"$('{p1}'+'{p2}')") # Less common, might need eval or backticks depending
                                # Alternative: 'p''a''r''t'
                                # obfuscated_parts.append("'" + "''".join(list(part)) + "'")
                        else:
                            obfuscated_parts.append(part)
                    obfuscated_command = " ".join(obfuscated_parts)
                    applied_obfuscation = "string_concatenation"
                except Exception as e:
                    self.logger.warning(f"String concatenation obfuscation failed: {e}. Using original command.")
            else:
                self.logger.warning("String concatenation obfuscation requested but method is not PowerShell/Bash. Obfuscation skipped.")

        # Add more obfuscation types here (e.g., environment variables, command substitution, etc.)

        else:
            self.logger.warning(f"Unsupported obfuscation type requested: '{obfuscation_type}'. No obfuscation applied.")

        if applied_obfuscation:
             self.logger.info(f"Applied obfuscation '{applied_obfuscation}'. Result preview: {obfuscated_command[:100]}...")
        return obfuscated_command, applied_obfuscation

    def _handle_command_execution(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a shell command with optional obfuscation."""
        original_command = data.get("cmd")
        method = data.get("method", "direct") # e.g., direct, powershell, bash
        obfuscation = data.get("obfuscation") # e.g., base64, caret, string_concat
        use_system_shell = data.get("use_shell_api", False) # Whether to use shell=True in subprocess
        capture_output = data.get("capture_output", True)
        run_in_background = data.get("background", False) # Note: True backgrounding is complex

        if not original_command:
             raise ValueError("Missing 'cmd' in command execution data.")
             
        self.logger.info(f"Handling command execution request: method={method}, obfuscation={obfuscation}, cmd={original_command}")
        
        # Apply obfuscation before determining final command/shell
        command_to_run, applied_obfuscation = self._apply_obfuscation(original_command, method, obfuscation)
        
        shell_to_use = self.config.get("default_shell")
        final_command_arg = command_to_run # This is what gets passed to _run_command

        if method == "powershell":
            shell_executable = "pwsh" if platform.system() != "Windows" else "powershell.exe"
            shell_to_use = shell_executable # Set the shell executable
            if applied_obfuscation == "base64_encoded_command":
                # command_to_run already holds the base64 string
                final_command_arg = f"{shell_executable} -EncodedCommand {command_to_run}"
                use_system_shell = False # Pass as args to executable
            else:
                # Wrap non-encoded command for powershell -Command
                ps_command_escaped = command_to_run.replace('"', '`"') # Basic escaping for embedding
                final_command_arg = f"{shell_executable} -Command \"{ps_command_escaped}\""
                use_system_shell = True # Use shell=True to interpret the wrapper

        elif method == "bash":
            shell_to_use = "bash"
            # If obfuscation applied, it's already in command_to_run for shell -c
            final_command_arg = command_to_run 
            use_system_shell = True # Use shell -c
            
        elif method == "cmd":
             shell_to_use = "cmd"
             # If obfuscation applied, it's already in command_to_run for cmd /c
             final_command_arg = command_to_run
             use_system_shell = True # Use cmd /c
             
        elif method == "direct":
             shell_to_use = None # Let subprocess handle executable path
             final_command_arg = command_to_run # Already potentially obfuscated (e.g., caret)
             use_system_shell = False
             # Note: Caret obfuscation might require use_system_shell=True if using cmd implicitly
             if applied_obfuscation == "cmd_caret_escaping" and platform.system() == "Windows":
                  self.logger.debug("Caret obfuscation used with direct method, might require system shell implicitly.")
                  # Consider setting use_system_shell = True here, but makes 'direct' less direct.
                  # User should preferably use method='cmd' for caret obfuscation.
        else:
            self.logger.warning(f"Unknown execution method '{method}', using direct execution logic.")
            shell_to_use = None
            final_command_arg = command_to_run
            use_system_shell = False
            
        details = {
            "original_command": original_command,
            "command_executed_arg": final_command_arg, # What was passed to subprocess
            "obfuscation_requested": obfuscation,
            "obfuscation_applied": applied_obfuscation,
            "execution_method": method,
            "used_system_shell_api": use_system_shell,
            "shell_invoked": shell_to_use,
            "captured_output": capture_output
        }
        
        # Note: True background execution requires more complex handling 
        # (e.g., Popen without wait, detaching process, managing handles)
        # This implementation focuses on simple synchronous execution for now.
        if run_in_background:
            self.logger.warning("Background execution requested but not fully implemented. Running synchronously.")
        
        try:
            # Pass final_command_arg to _run_command
            returncode, stdout, stderr = self._run_command(final_command_arg, shell_to_use, use_system_shell, capture_output)
            
            details["return_code"] = returncode
            if capture_output:
                 # Limit output size in report
                 max_out_len = 2048
                 details["stdout"] = stdout[:max_out_len] + ('...' if len(stdout) > max_out_len else '')
                 details["stderr"] = stderr[:max_out_len] + ('...' if len(stderr) > max_out_len else '')
            else:
                details["stdout"] = "(Output not captured)"
                details["stderr"] = "(Output not captured)"
                
            execution_status = "success" if returncode == 0 else "failure"
            
            # Determine MITRE technique based on method if possible
            mitre_id = "T1059" # Command and Scripting Interpreter (Default)
            mitre_name = "Command and Scripting Interpreter"
            if method == "powershell":
                mitre_id = "T1059.001"
                mitre_name = "Command and Scripting Interpreter: PowerShell"
            elif method == "cmd":
                mitre_id = "T1059.003"
                mitre_name = "Command and Scripting Interpreter: Windows Command Shell"
            elif method == "bash":
                mitre_id = "T1059.004"
                mitre_name = "Command and Scripting Interpreter: Unix Shell"
                
            result = {
                "status": execution_status,
                "technique": f"command_execution_{method}" + (f"_{applied_obfuscation}" if applied_obfuscation else ""),
                "mitre_technique_id": mitre_id,
                "mitre_technique_name": mitre_name,
                "timestamp": datetime.now().isoformat(),
                "details": details
            }
            self.logger.info(f"Command execution finished with status: {execution_status}")
            return result

        except (FileNotFoundError, TimeoutError, OSError) as specific_error:
             self.logger.error(f"Command execution failed: {specific_error}")
             raise # Re-raise specific known errors
        except Exception as e:
            self.logger.error(f"Error during command execution: {str(e)}", exc_info=True)
            raise # Re-raise unexpected errors
            
    def _log_error(self, message: str, exc_info: bool = False) -> None:
        """Log errors using the initialized logger."""
        self.logger.error(message, exc_info=exc_info)

# Example Usage (for testing)
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    execution_module = Execution()
    # execution_module.update_config({}) # Load actual config here if needed
    
    print("\n--- Testing Command Execution (Direct) ---")
    cmd_request_direct = {"execute": {"command": {"cmd": "whoami"}}}
    cmd_result_direct = execution_module.execute(cmd_request_direct)
    import json
    print(json.dumps(cmd_result_direct, indent=2))

    print("\n--- Testing Command Execution (PowerShell - Windows) ---")
    if platform.system() == "Windows":
        cmd_request_ps = {"execute": {"command": {"cmd": "Get-Process | Select-Object -First 3 Name, Id", "method": "powershell"}}}
        cmd_result_ps = execution_module.execute(cmd_request_ps)
        print(json.dumps(cmd_result_ps, indent=2))
    else:
        print("Skipping PowerShell test (not Windows)")

    print("\n--- Testing Command Execution (Bash - Non-Windows) ---")
    if platform.system() != "Windows":
        cmd_request_bash = {"execute": {"command": {"cmd": "echo 'Hello from Bash' && ls -la | head -n 5", "method": "bash"}}}
        cmd_result_bash = execution_module.execute(cmd_request_bash)
        print(json.dumps(cmd_result_bash, indent=2))
    else:
        print("Skipping Bash test (is Windows)")
        
    print("\n--- Testing Command Execution (Failure) ---")
    cmd_request_fail = {"execute": {"command": {"cmd": "nonexistent_command_12345", "method": "direct"}}}
    cmd_result_fail = execution_module.execute(cmd_request_fail)
    print(json.dumps(cmd_result_fail, indent=2))

    print("\n--- Testing Command Execution (PowerShell Base64 Obfuscation) ---")
    if platform.system() == "Windows":
        cmd_request_ps_b64 = {"execute": {"command": {"cmd": "Write-Host 'Hello from Base64 PS!'; $env:USERNAME", "method": "powershell", "obfuscation": "base64"}}}
        cmd_result_ps_b64 = execution_module.execute(cmd_request_ps_b64)
        print(json.dumps(cmd_result_ps_b64, indent=2))
    else:
        print("Skipping PowerShell Base64 test (not Windows)")

    print("\n--- Testing Command Execution (CMD Caret Obfuscation) ---")
    if platform.system() == "Windows":
        # Simple command that uses special chars
        cmd_request_caret = {"execute": {"command": {"cmd": "echo Hello & echo World | findstr World", "method": "cmd", "obfuscation": "caret"}}}
        cmd_result_caret = execution_module.execute(cmd_request_caret)
        print(json.dumps(cmd_result_caret, indent=2))
    else:
        print("Skipping CMD Caret test (not Windows)")

    print("\n--- Testing Command Execution (String Concat Obfuscation - Bash) ---")
    if platform.system() != "Windows":
        cmd_request_concat = {"execute": {"command": {"cmd": "whoami", "method": "bash", "obfuscation": "string_concat"}}}
        cmd_result_concat = execution_module.execute(cmd_request_concat)
        print(json.dumps(cmd_result_concat, indent=2))
    else:
        print("Skipping String Concat Bash test (is Windows)") 