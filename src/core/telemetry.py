"""
Telemetry Module
Handles sending events/logs to external monitoring systems like Splunk and Elasticsearch.
"""

import logging
import requests
import json
import base64
from typing import Dict, Any, Optional
from datetime import datetime
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

# Default timeout for HTTP requests
DEFAULT_TIMEOUT = 10 # seconds

class TelemetryManager:
    """Manages configuration and dispatching for telemetry endpoints."""
    def __init__(self):
        self.config = {}
        self.splunk_enabled = False
        self.elastic_enabled = False
        self.splunk_url: Optional[str] = None
        self.splunk_token: Optional[str] = None
        self.elastic_url: Optional[str] = None
        self.elastic_auth: Optional[Any] = None # Can be header dict, user/pass tuple
        self.session = requests.Session() # Use a session for connection reuse
        self.verify_ssl = True # Default to verifying SSL certs

    def update_config(self, global_config: Dict[str, Any]):
        """Updates telemetry configuration from the main config dictionary."""
        telemetry_config = global_config.get("telemetry", {})
        self.config = telemetry_config
        self.verify_ssl = telemetry_config.get("verify_ssl", True)

        # Splunk Configuration
        splunk_conf = telemetry_config.get("splunk", {})
        self.splunk_enabled = telemetry_config.get("enabled", False) and splunk_conf.get("enabled", False)
        if self.splunk_enabled:
            self.splunk_url = splunk_conf.get("host")
            self.splunk_token = splunk_conf.get("token")
            if not self.splunk_url or not self.splunk_token:
                logger.error(
                    "Splunk enabled but missing 'host' or 'token'. Disabling."
                )
                self.splunk_enabled = False
            else:
                 logger.info(f"Splunk telemetry enabled: {self.splunk_url}")
        else:
             logger.info("Splunk telemetry disabled.")

        # Elasticsearch Configuration
        elastic_conf = telemetry_config.get("elastic", {})
        self.elastic_enabled = telemetry_config.get("enabled", False) and elastic_conf.get("enabled", False)
        if self.elastic_enabled:
            self.elastic_url = elastic_conf.get("host")
            elastic_user = elastic_conf.get("username")
            elastic_pass = elastic_conf.get("password")
            elastic_api_key = elastic_conf.get("api_key")
            elastic_api_key_id = elastic_conf.get("api_key_id")

            if not self.elastic_url:
                logger.error(
                    "Elasticsearch enabled but missing 'host'. Disabling."
                )
                self.elastic_enabled = False
            else:
                # Prioritize API Key auth if both ID and Key are provided
                if elastic_api_key and elastic_api_key_id:
                     api_key_combined = f"{elastic_api_key_id}:{elastic_api_key}"
                     api_key_encoded = base64.b64encode(
                         api_key_combined.encode('utf-8')
                     ).decode('ascii')
                     self.elastic_auth = {"Authorization": f"ApiKey {api_key_encoded}"}
                     logger.info(f"Elasticsearch telemetry enabled (API Key): {self.elastic_url}")
                elif elastic_user and elastic_pass:
                    # Fallback to Basic Auth
                    self.elastic_auth = (elastic_user, elastic_pass)
                    logger.info(f"Elasticsearch telemetry enabled (Basic Auth): {self.elastic_url}")
                else:
                     # No authentication provided
                     self.elastic_auth = None
                     logger.warning(
                         f"Elasticsearch enabled without authentication: {self.elastic_url}"
                     )
        else:
             logger.info("Elasticsearch telemetry disabled.")

    def log_event(self, event_data: Dict[str, Any]):
        """Logs an event to all enabled telemetry endpoints."""
        if not isinstance(event_data, dict):
             logger.warning(f"Telemetry log_event expects dict, received {type(event_data)}.")
             return

        # Ensure timestamp exists
        event_data.setdefault("timestamp", datetime.now().isoformat())

        if self.splunk_enabled:
            self._send_to_splunk(event_data)

        if self.elastic_enabled:
            self._send_to_elasticsearch(event_data)

    def _send_to_splunk(self, event_data: Dict[str, Any]):
        """Sends a single event to Splunk HEC."""
        if not self.splunk_url or not self.splunk_token:
            logger.debug("Splunk send skipped: URL or Token missing.")
            return

        payload = json.dumps({"event": event_data})
        headers = {
            'Content-Type': 'application/json',
            "Authorization": f"Splunk {self.splunk_token}"
        }

        try:
            response = self.session.post(
                self.splunk_url,
                data=payload,
                headers=headers,
                timeout=DEFAULT_TIMEOUT,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            response_text_snippet = response.text[:100] + ('...' if len(response.text) > 100 else '')
            logger.debug(f"Event sent to Splunk. Response: {response_text_snippet}")
        except RequestException as e:
            # Log specific request errors
            logger.error(f"Error sending to Splunk ({self.splunk_url}): {e}")
        except Exception as e:
            # Log unexpected errors
            logger.error(f"Unexpected error sending to Splunk: {e}", exc_info=True)

    def _send_to_elasticsearch(self, event_data: Dict[str, Any]):
        """Sends a single event to Elasticsearch Bulk API."""
        if not self.elastic_url:
            logger.debug("Elasticsearch send skipped: URL missing.")
            return

        index_prefix = self.config.get("elastic", {}).get("index_prefix", "bluefire")
        index_name = f"{index_prefix}-{datetime.now().strftime('%Y.%m.%d')}"
        action_meta = json.dumps({"index": {"_index": index_name}})
        document = json.dumps(event_data)
        payload = f"{action_meta}\n{document}\n" # Must end with newline

        bulk_url = self.elastic_url.rstrip('/') + "/_bulk"
        headers = {'Content-Type': 'application/x-ndjson'}
        auth_to_use = None
        extra_headers = {}

        # Determine auth method
        if isinstance(self.elastic_auth, dict): # API Key header
             extra_headers = self.elastic_auth
        elif isinstance(self.elastic_auth, tuple): # Basic auth user/pass
             auth_to_use = self.elastic_auth

        try:
            response = self.session.post(
                bulk_url,
                data=payload.encode('utf-8'),
                headers={**headers, **extra_headers},
                auth=auth_to_use,
                timeout=DEFAULT_TIMEOUT,
                verify=self.verify_ssl
            )
            response.raise_for_status()

            # Check bulk response content for errors
            response_json = response.json()
            if response_json.get("errors"):
                 # Attempt to log the first error encountered in the bulk response
                 try:
                     first_item = response_json.get("items", [{}])[0]
                     op_type = list(first_item.keys())[0] if first_item else 'unknown_op'
                     error_details = first_item.get(op_type, {}).get("error", "Unknown bulk error")
                     logger.error(f"Error indexing to Elasticsearch: {error_details}")
                 except (IndexError, KeyError, Exception) as parse_err:
                      logger.error(f"Error parsing Elasticsearch bulk error response: {parse_err}. Full response (may be large): {response_json}")
            else:
                 logger.debug("Event sent to Elasticsearch successfully.")

        except RequestException as e:
            logger.error(f"Error sending to Elasticsearch ({bulk_url}): {e}")
        except json.JSONDecodeError as e:
             response_text = getattr(response, 'text', '[No Response Text]')
             logger.error(f"Error decoding ES JSON response: {e}. Response: {response_text[:500]}...")
        except Exception as e:
            logger.error(f"Unexpected error sending to Elasticsearch: {e}", exc_info=True)

# Consider creating/managing this instance within the main BlueFireNexus class
# telemetry_manager = TelemetryManager() 