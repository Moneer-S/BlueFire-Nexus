"""
Consolidated Discovery Module
Handles discovery for all APT implementations
"""

import os
import sys
import time
import random
import string
import hashlib
import base64
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
import logging
import platform
import psutil
import subprocess
import grp # For Linux/macOS group info
import pwd # For Linux/macOS user info
import ctypes # Added for Windows privilege check
import re # Import re for parsing

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    nmap = None # Placeholder

class Discovery:
    """Handles discovery for all APT implementations"""
    
    def __init__(self):
        # Initialize discovery techniques
        self.techniques = {
            "system": {
                "system_info": {
                    "description": "Use system information",
                    "indicators": ["system_info", "host_info"],
                    "evasion": ["system_hiding", "host_hiding"]
                },
                "process_info": {
                    "description": "Use process information",
                    "indicators": ["process_info", "runtime_info"],
                    "evasion": ["process_hiding", "runtime_hiding"]
                },
                "service_info": {
                    "description": "Use service information",
                    "indicators": ["service_info", "runtime_info"],
                    "evasion": ["service_hiding", "runtime_hiding"]
                }
            },
            "network": {
                "network_scan": {
                    "description": "Use network scanning",
                    "indicators": ["network_scan", "host_scan"],
                    "evasion": ["network_hiding", "host_hiding"]
                },
                "port_scan": {
                    "description": "Use port scanning",
                    "indicators": ["port_scan", "service_scan"],
                    "evasion": ["port_hiding", "service_hiding"]
                },
                "service_scan": {
                    "description": "Use service scanning",
                    "indicators": ["service_scan", "application_scan"],
                    "evasion": ["service_hiding", "application_hiding"]
                }
            },
            "account": {
                "user_info": {
                    "description": "Use user information",
                    "indicators": ["user_info", "account_info"],
                    "evasion": ["user_hiding", "account_hiding"]
                },
                "group_info": {
                    "description": "Use group information",
                    "indicators": ["group_info", "account_info"],
                    "evasion": ["group_hiding", "account_hiding"]
                },
                "privilege_info": {
                    "description": "Use privilege information",
                    "indicators": ["privilege_info", "account_info"],
                    "evasion": ["privilege_hiding", "account_hiding"]
                }
            }
        }
        
        # Initialize discovery tools
        self.tools = {
            "system": {
                "system_info_handler": self._handle_system_info,
                "process_info_handler": self._handle_process_info,
                "service_info_handler": self._handle_service_info,
                "network_config_handler": self._handle_network_config
            },
            "network": {
                "network_scan_handler": self._handle_network_scan,
                "port_scan_handler": self._handle_port_scan,
                "service_scan_handler": self._handle_service_scan
            },
            "account": {
                "user_info_handler": self._handle_user_info,
                "group_info_handler": self._handle_group_info,
                "privilege_info_handler": self._handle_privilege_info
            }
        }
        
        # Initialize configuration
        self.config = {
            "system": {
                "system_info": {
                    "commands": ["systeminfo", "hostname", "ver"],
                    "files": ["system", "host", "version"],
                    "timeouts": [30, 60, 120]
                },
                "process_info": {
                    "commands": ["tasklist", "ps", "top"],
                    "files": ["process", "task", "runtime"],
                    "timeouts": [30, 60, 120]
                },
                "service_info": {
                    "commands": ["sc", "service", "systemctl"],
                    "files": ["service", "daemon", "runtime"],
                    "timeouts": [30, 60, 120]
                }
            },
            "network": {
                "network_scan": {
                    "commands": ["nmap", "ping", "traceroute"],
                    "files": ["network", "host", "route"],
                    "timeouts": [30, 60, 120]
                },
                "port_scan": {
                    "commands": ["nmap", "netstat", "ss"],
                    "files": ["port", "service", "connection"],
                    "timeouts": [30, 60, 120]
                },
                "service_scan": {
                    "commands": ["nmap", "netstat", "ss"],
                    "files": ["service", "application", "connection"],
                    "timeouts": [30, 60, 120]
                }
            },
            "account": {
                "user_info": {
                    "commands": ["net user", "id", "whoami"],
                    "files": ["user", "account", "passwd"],
                    "timeouts": [30, 60, 120]
                },
                "group_info": {
                    "commands": ["net group", "groups", "id"],
                    "files": ["group", "account", "passwd"],
                    "timeouts": [30, 60, 120]
                },
                "privilege_info": {
                    "commands": ["whoami /priv", "sudo -l", "id"],
                    "files": ["privilege", "account", "passwd"],
                    "timeouts": [30, 60, 120]
                }
            },
            "discovery_timeout": 60,
            "process_info_attrs": ['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'create_time', 'status'],
            "nmap_path": ['nmap'], # Path to nmap executable for PortScanner, can be overridden in config
            "default_nmap_args": "-sV -T4", # Default args for nmap scans (Service Version, Timing Template 4)
            "default_host_discovery_args": "-sn -T4", # Ping Scan args
            "max_report_size": 5 * 1024 * 1024 # Limit report size (e.g., 5MB) to prevent excessive memory use
        }
        self.logger = logging.getLogger(__name__)
        
    def update_config(self, config: Dict[str, Any]):
        """Update internal config with loaded configuration."""
        discovery_config = config.get("discovery", {})
        # Merge deeply for nested configs like nmap_path
        for key, value in discovery_config.items():
            if isinstance(value, dict) and isinstance(self.config.get(key), dict):
                self.config[key].update(value)
            else:
                self.config[key] = value
        self.logger.info("Discovery module configuration updated.")
        
        # Check Nmap availability after config update
        if NMAP_AVAILABLE:
            try:
                # Initialize PortScanner with potential custom path from config
                self.scanner = nmap.PortScanner(nmap_search_path=tuple(self.config.get("nmap_path", ['nmap'])))
                self.logger.info(f"Nmap PortScanner initialized. Path search: {self.scanner.nmap_search_path()}")
            except nmap.nmap.PortScannerError as e:
                self.logger.error(f"Failed to initialize Nmap PortScanner (check nmap path in config?): {e}", exc_info=True)
                self.scanner = None # Mark scanner as unavailable
        else:
             self.scanner = None
             self.logger.warning("python-nmap library not found. Network scans will be limited or unavailable.")
        
        # Add helper for running commands if needed later
        self._execution_module = None 

    def set_execution_module(self, execution_module):
        """Sets the execution module dependency."""
        self._execution_module = execution_module
        self.logger.info("Execution module set for Discovery.")

    def _execute_command(self, command: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """Helper to execute a shell command using the Execution module."""
        if not self._execution_module:
            self.logger.error("Execution module not available for running command.")
            return {"status": "failure", "error": "Execution module not available"}
        
        # Use a simple command execution request structure
        request = {
            "execute": {
                "method": "command",
                "command": command,
                "timeout": timeout or self.config.get("discovery_timeout", 60)
            }
        }
        try:
            result = self._execution_module.execute(request)
            self.logger.debug(f"Command '{command}' executed via Execution module. Result: {result.get('status')}")
            return result
        except Exception as e:
            self.logger.error(f"Error executing command '{command}' via Execution module: {e}", exc_info=True)
            return {"status": "failure", "error": str(e)}

    def discover(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform discovery"""
        result = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "results": {}
        }
        errors = []

        discovery_requests = data.get("discover", {})

        if discovery_requests.get("system_info"):
            try:
                result["results"]["system_info"] = self._handle_system_info({})
            except Exception as e:
                errors.append(f"System Info Discovery failed: {e}")
                self._log_error(f"System Info Discovery failed: {e}")

        if discovery_requests.get("process_info"):
            process_config = discovery_requests["process_info"] if isinstance(discovery_requests["process_info"], dict) else {}
            try:
                result["results"]["process_info"] = self._handle_process_info(process_config)
            except Exception as e:
                errors.append(f"Process Info Discovery failed: {e}")
                self._log_error(f"Process Info Discovery failed: {e}")

        if discovery_requests.get("service_info"):
            service_config = discovery_requests["service_info"] if isinstance(discovery_requests["service_info"], dict) else {}
            try:
                result["results"]["service_info"] = self._handle_service_info(service_config)
            except Exception as e:
                errors.append(f"Service Info Discovery failed: {e}")
                self._log_error(f"Service Info Discovery failed: {e}")
        
        if discovery_requests.get("host_discovery"):
            host_config = discovery_requests["host_discovery"] if isinstance(discovery_requests["host_discovery"], dict) else {}
            try:
                result["results"]["host_discovery"] = self._handle_host_discovery(host_config)
            except Exception as e:
                errors.append(f"Host Discovery failed: {e}")
                self._log_error(f"Host Discovery failed: {e}")

        if discovery_requests.get("port_scan"):
            port_config = discovery_requests["port_scan"] if isinstance(discovery_requests["port_scan"], dict) else {}
            try:
                result["results"]["port_scan"] = self._handle_port_service_scan(port_config)
            except Exception as e:
                errors.append(f"Port Scan failed: {e}")
                self._log_error(f"Port Scan failed: {e}")

        if discovery_requests.get("service_scan"):
            service_scan_config = discovery_requests["service_scan"] if isinstance(discovery_requests["service_scan"], dict) else {}
            try:
                result["results"]["service_scan"] = self._handle_port_service_scan(service_scan_config)
            except Exception as e:
                errors.append(f"Service Scan failed: {e}")
                self._log_error(f"Service Scan failed: {e}")

        if discovery_requests.get("user_info"):
            user_config = discovery_requests["user_info"] if isinstance(discovery_requests["user_info"], dict) else {}
            try:
                result["results"]["user_info"] = self._handle_user_info(user_config)
            except Exception as e:
                errors.append(f"User Info Discovery failed: {e}")
                self._log_error(f"User Info Discovery failed: {e}")

        if discovery_requests.get("group_info"):
            group_config = discovery_requests["group_info"] if isinstance(discovery_requests["group_info"], dict) else {}
            try:
                result["results"]["group_info"] = self._handle_group_info(group_config)
            except Exception as e:
                errors.append(f"Group Info Discovery failed: {e}")
                self._log_error(f"Group Info Discovery failed: {e}")
        
        if discovery_requests.get("privilege_info"):
            priv_config = discovery_requests["privilege_info"] if isinstance(discovery_requests["privilege_info"], dict) else {}
            try:
                result["results"]["privilege_info"] = self._handle_privilege_info(priv_config)
            except Exception as e:
                errors.append(f"Privilege Info Discovery failed: {e}")
                self._log_error(f"Privilege Info Discovery failed: {e}")

        if discovery_requests.get("network_config"):
            try:
                result["results"]["network_config"] = self._handle_network_config({})
            except Exception as e:
                errors.append(f"Network Config Discovery failed: {e}")
                self._log_error(f"Network Config Discovery failed: {e}")

        if errors:
            result["status"] = "partial_failure"
            result["errors"] = errors
            
        self.logger.info(f"Starting discovery run. Requests: {list(discovery_requests.keys())}")
        return result
            
    def _handle_system_info(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Gathers basic system information."""
        self.logger.info("Starting system information discovery.")
        info = {}
        try:
            info['platform'] = platform.system()
            info['platform_release'] = platform.release()
            info['platform_version'] = platform.version()
            info['architecture'] = platform.machine()
            info['hostname'] = platform.node()
            info['processor'] = platform.processor()
            # User info
            try:
                info['user'] = os.getlogin()
            except OSError: # os.getlogin() might fail in some environments (e.g., no controlling tty)
                 try:
                    info['user'] = pwd.getpwuid(os.getuid()).pw_name if hasattr(os, 'getuid') else 'N/A'
                 except Exception:
                     info['user'] = 'N/A' # Fallback if everything fails

            # Add Python version as potentially useful info
            info['python_version'] = sys.version

            self.logger.info("System information gathered successfully.")
            return {"status": "success", "data": info}
        except Exception as e:
            self.logger.error(f"Error gathering system info: {e}", exc_info=True)
            return {"status": "failure", "error": str(e), "data": info} # Return partial data if possible

    def _handle_process_info(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Gathers information about running processes."""
        self.logger.info("Starting process information discovery.")
        processes = []
        # Get attributes to fetch from config, default to a basic set
        attrs = details.get("attributes", self.config.get("process_info_attrs", ['pid', 'name', 'username']))
        # Ensure essential attributes are always included if possible
        if 'pid' not in attrs: attrs.append('pid')
        if 'name' not in attrs: attrs.append('name')

        try:
            for proc in psutil.process_iter(attrs=attrs, ad_value=None):
                try:
                    pinfo = proc.info
                    # Convert create_time from timestamp to ISO format string if present
                    if 'create_time' in pinfo and pinfo['create_time'] is not None:
                        pinfo['create_time'] = datetime.fromtimestamp(pinfo['create_time']).isoformat()
                    processes.append(pinfo)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # Ignore processes that have terminated or are inaccessible
                    continue
                except Exception as proc_err:
                    # Log specific process error but continue iteration
                    self.logger.warning(f"Could not retrieve info for a process (PID likely reused or exited): {proc_err}")
                    continue # Continue with the next process

            self.logger.info(f"Gathered information for {len(processes)} processes.")
            return {"status": "success", "data": processes}
        except Exception as e:
            self.logger.error(f"Error gathering process list: {e}", exc_info=True)
            # Return partial list if error occurred mid-iteration? Maybe not reliable.
            return {"status": "failure", "error": str(e), "data": []}

    def _handle_service_info(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Gather service information using OS-specific commands."""
        self.logger.info("Starting service information discovery.")
        os_type = platform.system()
        services = []
        status = "failure"
        error_message = None
        command_used = ""

        try:
            if os_type == "Windows":
                command = ["sc", "query", "type=", "service", "state=", "all", "bufsize=", "65535"]
                command_used = " ".join(command)
                # Increase timeout potentialy needed for large service lists
                timeout = self.config.get("discovery_timeout", 60) * 2 
                result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout, errors='ignore')
                
                if result.returncode == 0:
                    services = self._parse_sc_query_output(result.stdout)
                    status = "success"
                else:
                    error_message = f"'sc query' failed with code {result.returncode}. Stderr: {result.stderr}"
                    self.logger.error(error_message)
            
            elif os_type == "Linux":
                # systemd is most common, check if available
                systemctl_path = "/bin/systemctl" # Or find dynamically?
                if os.path.exists(systemctl_path):
                    command = [systemctl_path, "list-units", "--type=service", "--all", "--no-pager"]
                    command_used = " ".join(command)
                    timeout = self.config.get("discovery_timeout", 60)
                    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout, errors='ignore')

                    if result.returncode == 0:
                        services = self._parse_systemctl_output(result.stdout)
                        status = "success"
                    else:
                        # Check if running as root is needed for --all
                        if "must be root" in result.stderr.lower():
                             error_message = f"'systemctl list-units' failed: Requires root privileges for full listing."
                        else:
                             error_message = f"'systemctl list-units' failed with code {result.returncode}. Stderr: {result.stderr}"
                        self.logger.error(error_message)
                else:
                     # Fallback or alternative for non-systemd systems (e.g., init.d scripts) - Simple placeholder for now
                     error_message = "systemctl not found. Service discovery for non-systemd Linux is not fully implemented."
                     self.logger.warning(error_message)
                     status = "not_implemented" 

            elif os_type == "Darwin": # macOS
                command = ["/bin/launchctl", "list"]
                command_used = " ".join(command)
                timeout = self.config.get("discovery_timeout", 60)
                result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout, errors='ignore')

                if result.returncode == 0:
                    services = self._parse_launchctl_output(result.stdout)
                    status = "success"
                else:
                    error_message = f"'launchctl list' failed with code {result.returncode}. Stderr: {result.stderr}"
                    self.logger.error(error_message)
            
            else:
                error_message = f"Unsupported OS for service discovery: {os_type}"
                self.logger.warning(error_message)
                status = "not_implemented"

        except FileNotFoundError as e:
            error_message = f"Required command not found: {e.filename}. Ensure system utilities are installed and in PATH."
            self.logger.error(error_message)
            status = "error_command_not_found"
        except subprocess.TimeoutExpired:
            error_message = f"Command '{command_used}' timed out after {timeout} seconds."
            self.logger.error(error_message)
            status = "error_timeout"
            except Exception as e:
            error_message = f"An unexpected error occurred during service discovery: {e}"
            self.logger.error(error_message, exc_info=True)
            status = "error_exception"

        self.logger.info(f"Service discovery finished with status: {status}. Found {len(services)} services.")
        return {"status": status, "services": services, "count": len(services), "command_used": command_used, "error": error_message}

    def _parse_sc_query_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse the output of 'sc query type= service state= all'"""
        services = []
        # Regex might be more robust, but string splitting is simpler for now
        current_service = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SERVICE_NAME:"):
                if current_service: # Save previous service before starting new one
                     services.append(current_service)
                current_service = {"name": line.split(":", 1)[1].strip()}
            elif line.startswith("DISPLAY_NAME:"):
                current_service["display_name"] = line.split(":", 1)[1].strip()
            elif line.startswith("STATE"): # Format: STATE              : 4  RUNNING
                parts = line.split(":", 1)[1].strip().split()
                if len(parts) >= 2:
                     current_service["state_code"] = parts[0]
                     current_service["state"] = parts[1]
            elif line.startswith("PID"): # Format: PID                : 1234
                parts = line.split(":", 1)[1].strip()
                if parts.isdigit():
                     current_service["pid"] = int(parts)
            # Add other fields if needed (e.g., TYPE, WIN32_EXIT_CODE)
        
        if current_service: # Add the last service found
            services.append(current_service)
            
        return services

    def _parse_systemctl_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse the output of 'systemctl list-units --type=service --all'"""
        services = []
        lines = output.splitlines()
        # Skip header line and potential footer lines
        for line in lines[1:]:
            line = line.strip()
            if not line or line.startswith("LOAD   ACTIVE SUB") or "loaded units listed" in line:
                continue
            # Basic parsing, assumes consistent column width which might break
            # Example: networkd-dispatcher.service loaded active running Network Manager Script Dispatcher Service
            parts = line.split(None, 4) 
            if len(parts) >= 4: # Need at least unit, load, active, sub
                service = {
                    "name": parts[0].replace("●", "").strip(), # Remove bullet point if present
                    "load": parts[1],
                    "active": parts[2],
                    "sub_state": parts[3],
                    "description": parts[4] if len(parts) > 4 else ""
                }
                # Determine a simplified overall state
                if service["active"] == "active":
                     service["state"] = "running"
                elif service["active"] == "inactive":
                     service["state"] = "stopped"
                elif service["active"] == "failed":
                     service["state"] = "failed"
                else:
                     service["state"] = service["active"] # e.g., activating, deactivating
                     
                services.append(service)
        return services
        
    def _parse_launchctl_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse the output of 'launchctl list'"""
        services = []
        lines = output.splitlines()
        # Skip header line
        if lines and lines[0].strip().startswith("PID"): # Basic header check
             lines = lines[1:]
             
        for line in lines:
            line = line.strip()
            if not line:
                continue
            # Format: PID Status Label
            parts = line.split(None, 2)
            if len(parts) == 3:
                pid_str, status_str, label = parts
                service = {"name": label, "status_code": status_str}
                # Try to interpret PID and status
                if pid_str != "-" and pid_str.isdigit():
                    service["pid"] = int(pid_str)
                    service["state"] = "running"
                else:
                    service["pid"] = None
                    # Status code might be an exit code or signal
                    service["state"] = "stopped" # Simplification
                services.append(service)
            # Handle potential lines with only label?
            elif len(parts) == 1:
                 services.append({"name": parts[0], "pid": None, "status_code": None, "state": "unknown"})
                 
        return services

    def _handle_network_config(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Gathers network interface configuration (IP addresses, MAC, etc.)."""
        self.logger.info("Starting network configuration discovery.")
        interfaces = {}
        try:
            # Get all network interfaces and their addresses
            all_interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats() # Get operational status (isup), speed, mtu

            for name, addrs in all_interfaces.items():
                interfaces[name] = {
                    "addresses": [],
                    "stats": stats.get(name, None) # Add stats if available
                }
                if interfaces[name]["stats"]: # Convert named tuple to dict for JSON serialization
                   interfaces[name]["stats"] = interfaces[name]["stats"]._asdict()

                for addr in addrs:
                    addr_info = {
                        "family": addr.family.name, # AF_INET (IPv4), AF_INET6 (IPv6), AF_LINK (MAC)
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast,
                        # ptp is for point-to-point interfaces
                        "ptp": addr.ptp if hasattr(addr, 'ptp') else None 
                    }
                    interfaces[name]["addresses"].append(addr_info)
            
            self.logger.info(f"Gathered configuration for {len(interfaces)} network interfaces.")
            return {"status": "success", "data": interfaces}
        except Exception as e:
            self.logger.error(f"Error gathering network configuration: {e}", exc_info=True)
            return {"status": "failure", "error": str(e), "data": {}} # Return empty data on error

    def _handle_host_discovery(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform host discovery (e.g., ping scan) using Nmap."""
        if not self.scanner:
            raise ConnectionError("Nmap scanner is not available or failed to initialize. Check installation and configuration.")
            
        targets = data.get("targets") # Expecting a string like "192.168.1.0/24" or "host1 host2"
        arguments = data.get("arguments", self.config.get("default_host_discovery_args", "-sn -T4"))
        sudo = data.get("sudo", False) # Whether to run nmap with sudo (needed for some scan types like SYN)
        
        if not targets:
            raise ValueError("Missing 'targets' parameter for host discovery.")
            
        self.logger.info(f"Starting host discovery on targets: {targets} with args: {arguments}")
        details = {}
        try:
            # Ensure scanner is available
            if not hasattr(self, 'scanner') or self.scanner is None:
                 raise ConnectionError("Nmap scanner was not properly initialized.")

            self.scanner.scan(hosts=targets, arguments=arguments, sudo=sudo)
            details["command_line"] = self.scanner.command_line()
            details["scan_stats"] = self.scanner.scanstats()
            details["hosts_up"] = []
            details["hosts_down"] = []
            
            all_hosts = self.scanner.all_hosts()
            for host in all_hosts:
                if self.scanner[host].state() == 'up':
                    host_info = {'host': host, 'status': 'up'}
                    # Add MAC address if available (often requires root/sudo)
                    if 'addresses' in self.scanner[host] and 'mac' in self.scanner[host]['addresses']:
                         host_info['mac'] = self.scanner[host]['addresses']['mac']
                    # Add vendor if available
                    if 'vendor' in self.scanner[host] and self.scanner[host]['vendor']:
                        # The vendor info might be nested
                        vendor_data = self.scanner[host]['vendor']
                        first_mac = next(iter(vendor_data)) if vendor_data else None
                        if first_mac:
                            host_info['vendor'] = vendor_data[first_mac]
                    details["hosts_up"].append(host_info)
                else:
                    details["hosts_down"].append({'host': host, 'status': self.scanner[host].state()})
                    
            result = {
                "status": "success",
                "technique": "host_discovery",
                "mitre_technique_id": "T1018", # Remote System Discovery
                "mitre_technique_name": "Remote System Discovery",
                "timestamp": datetime.now().isoformat(),
                "details": details
            }
            self.logger.info(f"Host discovery complete. Found {len(details['hosts_up'])} hosts up.")
            return result

        except nmap.nmap.PortScannerError as e:
            self.logger.error(f"Nmap PortScannerError during host discovery: {e}", exc_info=True)
            raise ConnectionError(f"Nmap error: {e}") # Raise a more general error
        except Exception as e:
            self.logger.error(f"Error during host discovery: {str(e)}", exc_info=True)
            raise
            
    def _handle_port_service_scan(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform port and service version scanning using Nmap."""
        if not self.scanner:
            raise ConnectionError("Nmap scanner is not available or failed to initialize. Check installation and configuration.")

        targets = data.get("targets")
        ports = data.get("ports") # e.g., "22,80,443", "1-1000"
        arguments = data.get("arguments", self.config.get("default_nmap_args", "-sV -T4"))
        sudo = data.get("sudo", False)
        
        if not targets:
            raise ValueError("Missing 'targets' parameter for port/service scan.")
            
        self.logger.info(f"Starting port/service scan on targets: {targets}, ports: {ports or 'default'}, args: {arguments}")
        details = {"hosts": []}
        try:
            # Ensure scanner is available
            if not hasattr(self, 'scanner') or self.scanner is None:
                 raise ConnectionError("Nmap scanner was not properly initialized.")

            self.scanner.scan(hosts=targets, ports=ports, arguments=arguments, sudo=sudo)
            details["command_line"] = self.scanner.command_line()
            details["scan_stats"] = self.scanner.scanstats()
            
            # Limit report size
            current_size = 0
            max_size = self.config.get("max_report_size", 5 * 1024 * 1024)

            for host in self.scanner.all_hosts():
                if self.scanner[host].state() == 'up':
                    host_data = {
                        'host': host,
                        'status': 'up',
                        'protocols': {}
                    }
                    if 'hostnames' in self.scanner[host]:
                         host_data['hostnames'] = self.scanner[host]['hostnames']
                    if 'addresses' in self.scanner[host]:
                         host_data['addresses'] = self.scanner[host]['addresses']
                    if 'vendor' in self.scanner[host] and self.scanner[host]['vendor']:
                         host_data['vendor'] = self.scanner[host]['vendor']
                    
                    protocols = self.scanner[host].all_protocols()
                    for proto in protocols: # e.g., 'tcp', 'udp'
                        host_data['protocols'][proto] = []
                        lport = sorted(self.scanner[host][proto].keys())
                        for port in lport:
                            port_info = self.scanner[host][proto][port]
                            host_data['protocols'][proto].append({
                                'port': port,
                                'state': port_info['state'],
                                'name': port_info['name'],
                                'product': port_info['product'],
                                'version': port_info['version'],
                                'extrainfo': port_info['extrainfo'],
                                'conf': port_info['conf'],
                                'cpe': port_info['cpe']
                            })
                    
                    # Check size before adding
                    host_data_str = str(host_data) # Estimate size
                    if current_size + len(host_data_str) > max_size:
                        self.logger.warning(f"Scan report size limit ({max_size} bytes) reached. Truncating results.")
                        details["truncated"] = True
                        break # Stop adding hosts
                    
                    details["hosts"].append(host_data)
                    current_size += len(host_data_str)
                    
            result = {
                "status": "success",
                "technique": "port_service_scan",
                "mitre_technique_id": "T1046", # Network Service Scanning
                "mitre_technique_name": "Network Service Scanning",
                "timestamp": datetime.now().isoformat(),
                "details": details
            }
            self.logger.info(f"Port/Service scan complete for {len(details['hosts'])} hosts.")
            return result
            
        except nmap.nmap.PortScannerError as e:
            self.logger.error(f"Nmap PortScannerError during port/service scan: {e}", exc_info=True)
            raise ConnectionError(f"Nmap error: {e}")
        except Exception as e:
            self.logger.error(f"Error during port/service scan: {str(e)}", exc_info=True)
            raise
            
    def _handle_user_info(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Gathers information about local user accounts."""
        self.logger.info("Starting user information discovery.")
        users = []
        errors = []
        status = "success"
        
        # Method 1: psutil.users() (cross-platform)
        try:
            psutil_users = psutil.users()
            for u in psutil_users:
                users.append(u._asdict()) # Convert named tuple to dict
            self.logger.info(f"Gathered {len(psutil_users)} user sessions using psutil.")
        except Exception as e:
            self.logger.warning(f"psutil.users() failed: {e}", exc_info=True)
            errors.append(f"psutil.users() failed: {str(e)}")
            status = "partial"
            
        # Method 2: OS-specific commands via Execution module (if available)
        command_output = None
        if platform.system() == "Windows":
            # Consider 'net user' but parsing is complex. Maybe 'wmic useraccount get name,sid'?
            # For simplicity, psutil is often sufficient for logged-in users.
            self.logger.info("Windows user enumeration relies primarily on psutil; 'net user' requires parsing.")
        elif platform.system() == "Linux":
            # 'getent passwd' usually gives a comprehensive list
            cmd_result = self._execute_command("getent passwd")
            if cmd_result.get("status") == "success":
                command_output = cmd_result.get("output", "")
                # Basic parsing - assumes standard /etc/passwd format
                parsed_users = []
                for line in command_output.strip().splitlines():
                    try:
                        parts = line.split(":")
                        if len(parts) >= 7:
                            parsed_users.append({
                                "username": parts[0],
                                "uid": int(parts[2]),
                                "gid": int(parts[3]),
                                "gecos": parts[4],
                                "home": parts[5],
                                "shell": parts[6]
                            })
                    except Exception as parse_err:
                         self.logger.warning(f"Failed to parse passwd line '{line}': {parse_err}")
                self.logger.info(f"Parsed {len(parsed_users)} users from 'getent passwd'. Merging with psutil data.")
                # Simple merge/add strategy (could be improved with better matching)
                existing_usernames = {u['name'] for u in users}
                for pu in parsed_users:
                     if pu['username'] not in existing_usernames:
                         users.append({"name": pu['username'], "uid": pu['uid'], "gid": pu['gid'], "home": pu['home'], "shell": pu['shell'], "source": "getent_passwd"})
            else:
                err_msg = f"'getent passwd' command failed: {cmd_result.get('error', 'Unknown error')}"
                self.logger.warning(err_msg)
                errors.append(err_msg)
                status = "partial"
        else: # macOS or other Unix
            self.logger.info(f"User enumeration for {platform.system()} relies on psutil.")
            # Could add 'dscl . -list /Users' for macOS if needed

        return {"status": status, "error": "; ".join(errors) if errors else None, "data": users}

    def _handle_group_info(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Gathers information about local groups."""
        self.logger.info("Starting group information discovery.")
        groups = []
        errors = []
        status = "success"

        if platform.system() == "Windows":
            # Use 'net localgroup' command
            cmd_result = self._execute_command("net localgroup")
            if cmd_result.get("status") == "success":
                output = cmd_result.get("output", "")
                # Basic parsing (can be fragile)
                try:
                    lines = output.splitlines()
                    start_index = -1
                    end_index = -1
                    for i, line in enumerate(lines):
                        if line.startswith("---"):
                            if start_index == -1: start_index = i + 1
                            else: end_index = i; break
                    if start_index != -1 and end_index != -1:
                        for line in lines[start_index:end_index]:
                            group_name = line.strip().lstrip('*')
                            if group_name:
                                groups.append({"name": group_name, "source": "net_localgroup"})
                    self.logger.info(f"Parsed {len(groups)} groups from 'net localgroup'.")
                except Exception as parse_err:
                    err_msg = f"Failed to parse 'net localgroup' output: {parse_err}"
                    self.logger.error(err_msg, exc_info=True)
                    errors.append(err_msg)
                    status = "partial"
            else:
                err_msg = f"'net localgroup' command failed: {cmd_result.get('error', 'Unknown error')}"
                self.logger.warning(err_msg)
                errors.append(err_msg)
                status = "partial"

        elif platform.system() == "Linux":
            # Use 'getent group' command
            cmd_result = self._execute_command("getent group")
            if cmd_result.get("status") == "success":
                output = cmd_result.get("output", "")
                try:
                    for line in output.strip().splitlines():
                        parts = line.split(":")
                        if len(parts) >= 4:
                             groups.append({
                                 "name": parts[0],
                                 "gid": int(parts[2]),
                                 "members": parts[3].split(',') if parts[3] else [],
                                 "source": "getent_group"
                             })
                    self.logger.info(f"Parsed {len(groups)} groups from 'getent group'.")
                except Exception as parse_err:
                    err_msg = f"Failed to parse 'getent group' output: {parse_err}"
                    self.logger.error(err_msg, exc_info=True)
                    errors.append(err_msg)
                    status = "partial"
            else:
                err_msg = f"'getent group' command failed: {cmd_result.get('error', 'Unknown error')}"
                self.logger.warning(err_msg)
                errors.append(err_msg)
                status = "partial"
        else: # macOS or other Unix
            # Could use 'dscl . -list /Groups' on macOS
            self.logger.warning(f"Group discovery not implemented for {platform.system()} using commands.")
            status = "not_implemented"
            errors.append(f"Group discovery via command not implemented for {platform.system()}")
            # Optionally use grp module (may not list all system groups)
            try:
                 for g in grp.getgrall():
                      groups.append({"name": g.gr_name, "gid": g.gr_gid, "members": g.gr_mem, "source": "grp_module"})
                 self.logger.info(f"Found {len(groups)} groups using grp module as fallback.")
                 if status == "not_implemented": status = "partial" # If command failed but this worked
            except Exception as grp_err:
                 self.logger.warning(f"Failed to list groups using grp module: {grp_err}")
                 if not groups: # Only add error if we have no groups at all
                      errors.append(f"grp module failed: {grp_err}")

        return {"status": status, "error": "; ".join(errors) if errors else None, "data": groups}

    def _handle_privilege_info(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Gathers information about the current user's privileges."""
        self.logger.info("Starting privilege information discovery.")
        privileges = {"is_admin": None, "details": None}
        errors = []
        status = "success"
        
        # Get current user
        current_user = "Unknown"
        try:
            current_user = os.getlogin()
        except OSError:
             try:
                 current_user = pwd.getpwuid(os.getuid()).pw_name if hasattr(os, 'getuid') else 'N/A'
             except Exception:
                 current_user = 'N/A'
        privileges["current_user"] = current_user

        # Platform-specific privilege checks
        if platform.system() == "Windows":
            # Check admin status using ctypes
            try:
                privileges["is_admin"] = ctypes.windll.shell32.IsUserAnAdmin() != 0
                self.logger.info(f"Windows admin check (IsUserAnAdmin): {privileges['is_admin']}")
            except AttributeError:
                err_msg = "Failed to call IsUserAnAdmin (shell32.dll not found or inaccessible?)"
                self.logger.warning(err_msg)
                errors.append(err_msg)
                status = "partial"
                privileges["is_admin"] = None # Unknown status
            except Exception as e:
                 err_msg = f"Error checking admin status with ctypes: {e}"
                 self.logger.error(err_msg, exc_info=True)
                 errors.append(err_msg)
                 status = "partial"
                 privileges["is_admin"] = None

            # Get detailed privileges using 'whoami /priv'
            cmd_result = self._execute_command("whoami /priv")
            if cmd_result.get("status") == "success":
                privileges["details"] = cmd_result.get("output", "")
                self.logger.info("Successfully retrieved privilege details using 'whoami /priv'.")
            else:
                err_msg = f"'whoami /priv' command failed: {cmd_result.get('error', 'Unknown error')}"
                self.logger.warning(err_msg)
                errors.append(err_msg)
                status = "partial"

        elif hasattr(os, 'geteuid'): # Linux, macOS, other Unix
            # Check if effective UID is 0 (root)
            try:
                 privileges["is_admin"] = (os.geteuid() == 0)
                 self.logger.info(f"Unix admin check (eUID==0): {privileges['is_admin']}")
            except Exception as e:
                 err_msg = f"Error checking eUID: {e}"
                 self.logger.error(err_msg, exc_info=True)
                 errors.append(err_msg)
                 status = "partial"
                 privileges["is_admin"] = None
            
            # Get user/group IDs using 'id'
            cmd_result = self._execute_command("id")
            if cmd_result.get("status") == "success":
                privileges["details"] = cmd_result.get("output", "")
                self.logger.info("Successfully retrieved user/group details using 'id'.")
            else:
                err_msg = f"'id' command failed: {cmd_result.get('error', 'Unknown error')}"
                self.logger.warning(err_msg)
                errors.append(err_msg)
                status = "partial"
            
            # Additionally, check sudo privileges if possible (complex to parse reliably)
            # cmd_result_sudo = self._execute_command("sudo -ln") # Non-interactive list
            # Add parsing logic if needed

        else:
             self.logger.warning("Privilege discovery not fully implemented for this platform.")
             status = "not_implemented"
             errors.append("Unsupported platform for privilege check")

        return {"status": status, "error": "; ".join(errors) if errors else None, "data": privileges}

    def _run_command(self, cmd: list[str], check_error: bool = False) -> tuple[int, str, str]:
        """Helper to run subprocess commands with timeout and error handling."""
        timeout = self.config.get("discovery_timeout", 60)
        self.logger.debug(f"Running command: {' '.join(cmd)}")
        try:
            process = subprocess.run(cmd, capture_output=True, text=True, check=check_error, 
                                     timeout=timeout, encoding='utf-8', errors='ignore')
            self.logger.debug(f"Command finished. Return code: {process.returncode}")
            return process.returncode, process.stdout, process.stderr
        except FileNotFoundError:
            self.logger.error(f"Command not found: {cmd[0]}")
            raise FileNotFoundError(f"Required command '{cmd[0]}' not found.")
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            raise TimeoutError(f"Command '{cmd[0]}' timed out.")
        except subprocess.CalledProcessError as e:
             self.logger.error(f"Command '{' '.join(cmd)}' failed with return code {e.returncode}. Stderr: {e.stderr}")
             # Don't raise here if check_error is False, return the outputs
             return e.returncode, e.stdout, e.stderr 
        except Exception as e:
            self.logger.error(f"Unexpected error running command '{' '.join(cmd)}': {e}", exc_info=True)
            raise # Re-raise unexpected errors
            
    def _log_error(self, message: str) -> None:
        """Log error message"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, "discovery.log")
        with open(log_file, "a") as f:
            f.write(f"[{timestamp}] ERROR: {message}\n")
            
    def _generate_random_string(self, length: int = 8) -> str:
        """Generate a random string of specified length"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length)) 

# --- Example Usage --- 
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    discovery_module = Discovery()
    config_example = {
        "discovery": {
            "nmap_path": ['C:\\Program Files (x86)\\Nmap\\nmap.exe'] if platform.system() == "Windows" else ['/usr/bin/nmap', '/usr/local/bin/nmap'],
            "discovery_timeout": 120
        }
    }
    discovery_module.update_config(config_example) 
    
    # ... (previous sys_info, proc_info, service_info tests) ...

    # print("\n--- Testing Host Discovery ---")
    # host_disc_request = {"discover": {"host_discovery": {"targets": "192.168.1.0/24", "sudo": False}}}
    # host_disc_result = discovery_module.discover(host_disc_request)
    # print(json.dumps(host_disc_result, indent=2))

    # print("\n--- Testing Port/Service Scan ---")
    # port_scan_request = {"discover": {"port_service_scan": {"targets": "scanme.nmap.org", "ports": "22,80", "sudo": False}}}
    # port_scan_result = discovery_module.discover(port_scan_request)
    # print(json.dumps(port_scan_result, indent=2))

    print("\n--- Testing User Info ---")
    user_info_request = {"discover": {"user_info": True}}
    user_info_result = discovery_module.discover(user_info_request)
    print(json.dumps(user_info_result, indent=2))

    print("\n--- Testing Group Info ---")
    group_info_request = {"discover": {"group_info": True}}
    group_info_result = discovery_module.discover(group_info_request)
    print(json.dumps(group_info_result, indent=2))

    print("\n--- Testing Privilege Info ---")
    priv_info_request = {"discover": {"privilege_info": True}}
    priv_info_result = discovery_module.discover(priv_info_request)
    print(json.dumps(priv_info_result, indent=2)) 