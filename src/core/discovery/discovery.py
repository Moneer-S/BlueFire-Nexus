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
                "service_info_handler": self._handle_service_info
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

        if discovery_requests.get("port_service_scan"):
            scan_config = discovery_requests["port_service_scan"] if isinstance(discovery_requests["port_service_scan"], dict) else {}
            try:
                result["results"]["port_service_scan"] = self._handle_port_service_scan(scan_config)
            except Exception as e:
                errors.append(f"Port/Service Scan failed: {e}")
                self._log_error(f"Port/Service Scan failed: {e}")

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

        if errors:
            result["status"] = "partial_success" if result["results"] else "failure"
            result["errors"] = errors
            
        return result
            
    def _handle_system_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Gather basic system information using platform and psutil."""
        self.logger.info("Gathering system information.")
        details = {}
        try:
            uname = platform.uname()
            details["system"] = uname.system
            details["node_name"] = uname.node
            details["release"] = uname.release
            details["version"] = uname.version
            details["machine"] = uname.machine
            details["processor"] = uname.processor
            details["hostname"] = platform.node()
            details["fqdn"] = ""
            try:
                import socket
                details["fqdn"] = socket.getfqdn()
            except Exception:
                self.logger.warning("Could not determine FQDN.")

            boot_time_timestamp = psutil.boot_time()
            bt = datetime.fromtimestamp(boot_time_timestamp)
            details["boot_time"] = bt.strftime("%Y-%m-%d %H:%M:%S")

            cpufreq = psutil.cpu_freq()
            details["cpu"] = {
                "physical_cores": psutil.cpu_count(logical=False),
                "total_cores": psutil.cpu_count(logical=True),
                "max_frequency_mhz": cpufreq.max if cpufreq else "N/A",
                "min_frequency_mhz": cpufreq.min if cpufreq else "N/A",
                "current_frequency_mhz": cpufreq.current if cpufreq else "N/A",
                "usage_percent": psutil.cpu_percent(interval=1)
            }

            svmem = psutil.virtual_memory()
            details["memory"] = {
                "total_gb": round(svmem.total / (1024**3), 2),
                "available_gb": round(svmem.available / (1024**3), 2),
                "used_gb": round(svmem.used / (1024**3), 2),
                "percentage_used": svmem.percent
            }
            
            try:
                swap = psutil.swap_memory()
                details["swap_memory"] = {
                    "total_gb": round(swap.total / (1024**3), 2),
                    "free_gb": round(swap.free / (1024**3), 2),
                    "used_gb": round(swap.used / (1024**3), 2),
                    "percentage_used": swap.percent
                }
            except Exception:
                 details["swap_memory"] = "Not Available"

            details["disks"] = []
            partitions = psutil.disk_partitions()
            for partition in partitions:
                 try:
                      partition_usage = psutil.disk_usage(partition.mountpoint)
                      details["disks"].append({
                           "device": partition.device,
                           "mountpoint": partition.mountpoint,
                           "fstype": partition.fstype,
                           "total_gb": round(partition_usage.total / (1024**3), 2),
                           "used_gb": round(partition_usage.used / (1024**3), 2),
                           "free_gb": round(partition_usage.free / (1024**3), 2),
                           "percentage_used": partition_usage.percent
                      })
                 except Exception as e:
                      self.logger.warning(f"Could not get usage for disk {partition.device}: {e}")
                      details["disks"].append({
                           "device": partition.device,
                           "mountpoint": partition.mountpoint,
                           "fstype": partition.fstype,
                           "error": f"Could not retrieve usage: {e}"
                      })

            details["network_interfaces"] = []
            if_addrs = psutil.net_if_addrs()
            for interface_name, interface_addresses in if_addrs.items():
                addrs = []
                for address in interface_addresses:
                    addr_info = {"family": str(address.family).split('.')[-1]}
                    if address.address: addr_info["address"] = address.address
                    if address.netmask: addr_info["netmask"] = address.netmask
                    if address.broadcast: addr_info["broadcast"] = address.broadcast
                    addrs.append(addr_info)
                details["network_interfaces"].append({"name": interface_name, "addresses": addrs})

            result = {
                "status": "success",
                "technique": "system_info_discovery",
                "mitre_technique_id": "T1082",
                "mitre_technique_name": "System Information Discovery",
                "timestamp": datetime.now().isoformat(),
                "details": details
            }
            self.logger.info("Successfully gathered system information.")
            return result
        except Exception as e:
            self.logger.error(f"Error gathering system info: {str(e)}", exc_info=True)
            raise

    def _handle_process_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Gather running process information using psutil."""
        self.logger.info("Gathering process information.")
        process_list = []
        attrs = data.get("attrs", self.config.get("process_info_attrs", ['pid', 'name', 'username'])) 
        required_attrs = {'pid', 'name'}
        final_attrs = list(required_attrs.union(set(attrs)))
        
        try:
            for proc in psutil.process_iter(attrs=final_attrs, ad_value=None):
                 try:
                    pinfo = proc.info
                    if 'create_time' in pinfo and pinfo['create_time']:
                         pinfo['create_time'] = datetime.fromtimestamp(pinfo['create_time']).isoformat()
                    process_list.append(pinfo)
                 except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                      self.logger.debug(f"Skipping inaccessible process {proc.pid if hasattr(proc, 'pid') else 'unknown'}")
                      pass
                 except Exception as e:
                      self.logger.warning(f"Could not get full info for process {proc.pid if hasattr(proc, 'pid') else 'unknown'}: {e}")
                      try:
                           minimal_info = {'pid': proc.pid, 'name': proc.name(), 'error': f"Partial info due to: {e}"}
                           process_list.append(minimal_info)
                      except Exception:
                           pass

            result = {
                "status": "success",
                "technique": "process_discovery",
                "mitre_technique_id": "T1057",
                "mitre_technique_name": "Process Discovery",
                "timestamp": datetime.now().isoformat(),
                "details": {"processes": process_list, "count": len(process_list)}
            }
            self.logger.info(f"Successfully gathered information for {len(process_list)} processes.")
            return result
        except Exception as e:
            self.logger.error(f"Error gathering process info: {str(e)}", exc_info=True)
            raise

    def _handle_service_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Gather service information (OS-dependent)."""
        self.logger.info("Gathering service information.")
        services = []
        os_type = platform.system()
        
        try:
            if os_type == "Windows":
                 try:
                      for service in psutil.win_service_iter():
                           try:
                                service_info = service.as_dict()
                                services.append(service_info)
                           except psutil.NoSuchProcess:
                                self.logger.warning(f"Service '{service.name()}' process not found, skipping.")
                           except psutil.AccessDenied:
                                self.logger.warning(f"Access denied for service '{service.name()}', skipping.")
                           except Exception as e:
                                self.logger.warning(f"Could not get full info for service '{service.name()}': {e}")
                                try:
                                     services.append({"name": service.name(), "error": f"Partial info due to: {e}"})
                                except Exception: pass
                 except ImportError:
                      self.logger.warning("psutil win_service_iter not available on this system. Attempting 'sc query'.")
                      try:
                           cmd = ["sc", "query", "state=", "all", "bufsize=", "65535"]
                           timeout = self.config.get("discovery_timeout", 60)
                           process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout, encoding='utf-8', errors='ignore')
                           
                           if process.returncode == 0 and process.stdout:
                                services.append({"raw_output": process.stdout, "parse_status": "Requires parsing"})
                                current_service = {}
                                for line in process.stdout.splitlines():
                                     if line.startswith("SERVICE_NAME:"):
                                          if current_service:
                                               services.append(current_service)
                                          current_service = {"name": line.split(":", 1)[1].strip()}
                                     elif ":" in line and current_service:
                                          key, val = line.split(":", 1)
                                          key_clean = key.strip().lower().replace(" ", "_")
                                          current_service[key_clean] = val.strip()
                                if current_service:
                                     services.append(current_service)
                                if len(services) > 1 and "raw_output" in services[0]:
                                     services.pop(0)
                           else:
                                self.logger.error(f"'sc query' failed or returned empty. Code: {process.returncode}, Error: {process.stderr}")
                                raise OSError(f"'sc query' failed: {process.stderr or 'No output'}")
                      except FileNotFoundError:
                           self.logger.error("'sc' command not found. Cannot list Windows services.")
                           raise FileNotFoundError("'sc' command not found.")
                      except subprocess.TimeoutExpired:
                           self.logger.error("'sc query' timed out.")
                           raise TimeoutError("'sc query' timed out.")
                      except Exception as e:
                           self.logger.error(f"Failed to list Windows services using 'sc query': {e}", exc_info=True)
                           raise

            elif os_type == "Linux":
                try:
                    cmd = ["systemctl", "list-units", "--type=service", "--all", "--no-pager"]
                    timeout = self.config.get("discovery_timeout", 60)
                    process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout)

                    if process.returncode == 0 and process.stdout:
                         lines = process.stdout.strip().splitlines()
                         if len(lines) > 1:
                              for line in lines[1:-1]:
                                   parts = line.strip().split(None, 4)
                                   if len(parts) >= 4:
                                        name = parts[0].lstrip('●*').strip()
                                        load = parts[1]
                                        active = parts[2]
                                        sub = parts[3]
                                        description = parts[4] if len(parts) > 4 else ""
                                        services.append({
                                             "name": name,
                                             "load": load,
                                             "active": active,
                                             "sub": sub,
                                             "description": description,
                                             "source": "systemctl"
                                        })
                    else:
                         self.logger.warning(f"'systemctl' command failed or returned no units. Code: {process.returncode}, Error: {process.stderr}")
                         try:
                              for service in psutil.service_iter():
                                   service_info = service.as_dict()
                                   service_info["source"] = "psutil"
                                   services.append(service_info)
                              if not services: raise NotImplementedError
                         except (AttributeError, NotImplementedError, ImportError):
                              self.logger.warning("psutil service iteration not available or did not find services. Cannot list Linux services definitively.")

                except FileNotFoundError:
                    self.logger.error("'systemctl' command not found. Cannot list systemd services.")
                    try:
                         for service in psutil.service_iter():
                              service_info = service.as_dict()
                              service_info["source"] = "psutil"
                              services.append(service_info)
                         if not services: raise NotImplementedError
                    except (AttributeError, NotImplementedError, ImportError):
                         self.logger.warning("psutil service iteration not available. Cannot list Linux services.")
                         raise NotImplementedError("No known method available to list Linux services on this system.")
                except subprocess.TimeoutExpired:
                    self.logger.error("'systemctl list-units' timed out.")
                    raise TimeoutError("'systemctl list-units' timed out.")
                except Exception as e:
                    self.logger.error(f"Failed to list Linux services using 'systemctl': {e}", exc_info=True)
                    try:
                         for service in psutil.service_iter():
                              service_info = service.as_dict()
                              service_info["source"] = "psutil"
                              services.append(service_info)
                         if not services: raise NotImplementedError
                    except (AttributeError, NotImplementedError, ImportError):
                         self.logger.warning("psutil service iteration not available.")
                         raise

            elif os_type == "Darwin":
                 try:
                      cmd = ["launchctl", "list"]
                      timeout = self.config.get("discovery_timeout", 60)
                      process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout)
                      if process.returncode == 0 and process.stdout:
                           lines = process.stdout.strip().splitlines()
                           if len(lines) > 1:
                                for line in lines[1:]:
                                     parts = line.strip().split(None, 2)
                                     pid = parts[0] if parts[0] != '-' else None
                                     status = parts[1] if len(parts) > 1 and parts[1] != '-' else None
                                     label = parts[2] if len(parts) > 2 else None
                                     services.append({"pid": pid, "status": status, "label": label, "source": "launchctl"})
                      else:
                           self.logger.error(f"'launchctl list' failed or returned empty. Code: {process.returncode}, Error: {process.stderr}")
                           raise OSError(f"'launchctl list' failed: {process.stderr or 'No output'}")
                 except FileNotFoundError:
                      self.logger.error("'launchctl' command not found. Cannot list macOS services.")
                      raise FileNotFoundError("'launchctl' command not found.")
                 except subprocess.TimeoutExpired:
                      self.logger.error("'launchctl list' timed out.")
                      raise TimeoutError("'launchctl list' timed out.")
                 except Exception as e:
                      self.logger.error(f"Failed to list macOS services using 'launchctl': {e}", exc_info=True)
                      raise

            else:
                raise NotImplementedError(f"Service discovery not implemented for OS type: {os_type}")

            result = {
                "status": "success",
                "technique": "service_discovery",
                "mitre_technique_id": "T1543.003",
                "mitre_technique_name": "System Service Discovery",
                "timestamp": datetime.now().isoformat(),
                "details": {"services": services, "count": len(services)}
            }
            self.logger.info(f"Successfully gathered information for {len(services)} services on {os_type}.")
            return result

        except (NotImplementedError, FileNotFoundError, TimeoutError, OSError) as specific_error:
             self.logger.error(f"Service discovery failed: {specific_error}")
             raise
        except Exception as e:
            self.logger.error(f"Error gathering service info: {str(e)}", exc_info=True)
            raise
        
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
            
    def _handle_user_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Gather user account information (OS-dependent)."""
        self.logger.info("Gathering user information.")
        details = {"users": [], "current_user": {}}
        os_type = platform.system()
        
        try:
            # Current user always useful
            try:
                details["current_user"]["login_name"] = os.getlogin()
            except OSError:
                self.logger.warning("Could not get login name via os.getlogin().")
                details["current_user"]["login_name"] = "Unavailable"
            
            if os_type == "Windows":
                # Get current user details more reliably
                ret, out, err = self._run_command(["whoami", "/all"])
                if ret == 0:
                    details["current_user"]["whoami_all"] = out # Rich info, needs parsing if specific fields wanted
                else: 
                    self.logger.warning(f"'whoami /all' failed: {err}")
                    ret_simple, out_simple, _ = self._run_command(["whoami"])
                    if ret_simple == 0: details["current_user"]["username"] = out_simple.strip()

                # List all local users
                ret, out, err = self._run_command(["net", "user"])
                if ret == 0:
                    # Basic parsing of `net user` output
                    lines = out.splitlines()
                    user_lines = []
                    in_users_section = False
                    for line in lines:
                         if line.startswith("User accounts for"): continue
                         if line.startswith("-----"): 
                              in_users_section = True
                              continue
                         if line.startswith("The command completed successfully"): 
                              in_users_section = False
                              continue
                         if in_users_section and line.strip():
                              user_lines.extend(line.split()) # Handles multiple users per line
                    details["users"] = [{"username": user, "source": "net user"} for user in user_lines]
                else:
                    self.logger.warning(f"'net user' command failed: {err}")
                    details["users_error"] = f"'net user' failed: {err}"
            
            elif os_type in ["Linux", "Darwin"]:
                # Current user via id
                ret, out, err = self._run_command(["id"])
                if ret == 0: details["current_user"]["id_output"] = out.strip()
                else: self.logger.warning(f"'id' command failed: {err}")

                # List all users from passwd
                try:
                    pwd_users = pwd.getpwall()
                    details["users"] = [
                        {
                            "username": user.pw_name,
                            "uid": user.pw_uid,
                            "gid": user.pw_gid,
                            "gecos": user.pw_gecos, # Full name / comments
                            "home_dir": user.pw_dir,
                            "shell": user.pw_shell,
                            "source": "pwd.getpwall"
                        } for user in pwd_users
                    ]
                except Exception as e:
                    self.logger.error(f"Failed to list users using pwd module: {e}", exc_info=True)
                    details["users_error"] = f"Failed using pwd module: {e}"
                    # Fallback attempt: parsing /etc/passwd?

            else:
                raise NotImplementedError(f"User discovery not implemented for OS type: {os_type}")

            result = {
                "status": "success",
                "technique": "user_discovery",
                "mitre_technique_id": "T1087.001", # Account Discovery: Local Account
                "mitre_technique_name": "Account Discovery: Local Account",
                "timestamp": datetime.now().isoformat(),
                "details": details
            }
            self.logger.info(f"Successfully gathered user information for {os_type}.")
            return result

        except (NotImplementedError, FileNotFoundError, TimeoutError, OSError) as specific_error:
             self.logger.error(f"User discovery failed: {specific_error}")
             raise
        except Exception as e:
            self.logger.error(f"Error gathering user info: {str(e)}", exc_info=True)
            raise

    def _handle_group_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Gather group information (OS-dependent)."""
        self.logger.info("Gathering group information.")
        details = {"groups": [], "current_user_groups": []}
        os_type = platform.system()

        try:
            if os_type == "Windows":
                # Get current user's groups
                ret, out, err = self._run_command(["whoami", "/groups"])
                if ret == 0:
                    details["current_user_groups"] = out.strip() # Needs parsing for specific groups
                else:
                    self.logger.warning(f"'whoami /groups' failed: {err}")

                # List local groups
                ret, out, err = self._run_command(["net", "localgroup"])
                if ret == 0:
                    # Basic parsing of `net localgroup` output
                    lines = out.splitlines()
                    group_lines = []
                    in_groups_section = False
                    for line in lines:
                         if line.startswith("Aliases for"): continue
                         if line.startswith("-----"): 
                              in_groups_section = True
                              continue
                         if line.startswith("The command completed successfully"): 
                              in_groups_section = False
                              continue
                         if in_groups_section and line.strip():
                              # Group names might have spaces
                              if line.startswith("*"): # Group names start with *
                                   group_lines.append(line[1:].strip())
                    details["groups"] = [{"groupname": group, "source": "net localgroup"} for group in group_lines]
                else:
                    self.logger.warning(f"'net localgroup' command failed: {err}")
                    details["groups_error"] = f"'net localgroup' failed: {err}"
            
            elif os_type in ["Linux", "Darwin"]:
                # Current user's groups via id
                ret, out, err = self._run_command(["id"])
                if ret == 0:
                    # Parse `id` output for groups
                    id_output = out.strip()
                    details["current_user_groups"] = id_output # Keep raw for now, parsing is complex
                    # Example parsing (can be brittle):
                    try:
                         groups_part = id_output.split("groups=")[1]
                         groups_raw = groups_part.split() # Split on space
                         parsed_groups = []
                         for g in groups_raw:
                              gid_str, name_part = g.split("(", 1)
                              name = name_part.rstrip(')')
                              parsed_groups.append({"gid": int(gid_str), "name": name})
                         details["current_user_groups_parsed"] = parsed_groups
                    except Exception as parse_err:
                         self.logger.warning(f"Could not parse groups from 'id' output: {parse_err}")
                else:
                    self.logger.warning(f"'id' command failed: {err}")

                # List all groups from grp module
                try:
                    all_groups = grp.getgrall()
                    details["groups"] = [
                        {
                            "groupname": group.gr_name,
                            "gid": group.gr_gid,
                            "members": group.gr_mem,
                            "source": "grp.getgrall"
                        } for group in all_groups
                    ]
                except Exception as e:
                    self.logger.error(f"Failed to list groups using grp module: {e}", exc_info=True)
                    details["groups_error"] = f"Failed using grp module: {e}"
                    # Fallback attempt: parsing /etc/group?
            else:
                raise NotImplementedError(f"Group discovery not implemented for OS type: {os_type}")

            result = {
                "status": "success",
                "technique": "group_discovery",
                "mitre_technique_id": "T1069.001", # Permission Groups Discovery: Local Groups
                "mitre_technique_name": "Permission Groups Discovery: Local Groups",
                "timestamp": datetime.now().isoformat(),
                "details": details
            }
            self.logger.info(f"Successfully gathered group information for {os_type}.")
            return result

        except (NotImplementedError, FileNotFoundError, TimeoutError, OSError) as specific_error:
             self.logger.error(f"Group discovery failed: {specific_error}")
             raise
        except Exception as e:
            self.logger.error(f"Error gathering group info: {str(e)}", exc_info=True)
            raise

    def _handle_privilege_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Gather current user privilege information (OS-dependent)."""
        self.logger.info("Gathering privilege information for current user.")
        details = {}
        os_type = platform.system()

        try:
            if os_type == "Windows":
                ret, out, err = self._run_command(["whoami", "/priv"])
                if ret == 0:
                    details["privileges"] = []
                    # Parse `whoami /priv` output
                    lines = out.splitlines()
                    if len(lines) > 2: # Header lines
                        for line in lines[2:]:
                            parts = line.split(None, 2) # Split on whitespace, max 2 splits
                            if len(parts) == 3:
                                details["privileges"].append({"name": parts[0], "description": parts[1], "state": parts[2]})
                            elif len(parts) > 0 and parts[0]: # Handle cases with only name maybe?
                                details["privileges"].append({"name": parts[0], "description": "", "state": ""})
                else:
                    self.logger.warning(f"'whoami /priv' command failed: {err}")
                    details["privileges_error"] = f"'whoami /priv' failed: {err}"

                # Check for admin privileges (simple check)
                try:
                    # Requires pywin32 usually, or ctypes - keep it simple with command
                    ret_admin, _, err_admin = self._run_command(["net", "session"], check_error=False) # Fails if not admin
                    details["is_admin"] = (ret_admin == 0)
                    if ret_admin != 0 and ret_admin != 2: # 0 = success, 2 = access denied (expected for non-admin) 
                        self.logger.warning(f"'net session' command returned unexpected code {ret_admin}: {err_admin}")
                except FileNotFoundError:
                     details["is_admin"] = "Unknown ('net' command not found)"
                except Exception as admin_e:
                     self.logger.warning(f"Error checking admin status via 'net session': {admin_e}")
                     details["is_admin"] = "Unknown (Error during check)"

            elif os_type in ["Linux", "Darwin"]:
                # Check UID
                uid = os.geteuid()
                details["uid"] = uid
                details["is_root"] = (uid == 0)

                # Check sudo privileges
                if not details["is_root"]:
                    # Use -n to avoid password prompt, -l to list privileges
                    ret, out, err = self._run_command(["sudo", "-n", "-l"], check_error=False)
                    if ret == 0: # Sudo access without password, or listing allowed
                        details["sudo_privileges"] = out.strip()
                        details["sudo_status"] = "Passwordless or listing allowed"
                    elif ret == 1 and "password is required" in (err or "").lower():
                         details["sudo_status"] = "Password required (cannot list without prompt)"
                    elif ret == 1 and "may not run sudo" in (err or "").lower():
                         details["sudo_status"] = "Not allowed"
                    else:
                         self.logger.warning(f"'sudo -n -l' returned unexpected code {ret}: {err}")
                         details["sudo_status"] = f"Unknown (Code: {ret}, Error: {err})"
                else:
                    details["sudo_status"] = "User is root"
            else:
                raise NotImplementedError(f"Privilege discovery not implemented for OS type: {os_type}")

            result = {
                "status": "success",
                "technique": "privilege_discovery",
                # No single perfect MITRE ID, relates to T1087, T1069, T1548
                "mitre_technique_id": "T1087/T1069/T1548", 
                "mitre_technique_name": "Privilege/Account/Group Discovery", 
                "timestamp": datetime.now().isoformat(),
                "details": details
            }
            self.logger.info(f"Successfully gathered privilege information for {os_type}.")
            return result

        except (NotImplementedError, FileNotFoundError, TimeoutError, OSError) as specific_error:
             self.logger.error(f"Privilege discovery failed: {specific_error}")
             raise
        except Exception as e:
            self.logger.error(f"Error gathering privilege info: {str(e)}", exc_info=True)
            raise

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