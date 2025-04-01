import os
from pathlib import Path
import yaml
from typing import Dict, Any, Optional
from dotenv import load_dotenv

class ConfigManager:
    """Manages configuration for BlueFire-Nexus."""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self._load_env()
        self._load_config()
    
    def _load_env(self) -> None:
        """Load environment variables from .env file."""
        load_dotenv()
        
        # Default environment variables
        self.env_vars = {
            "BLUEFIRE_KILLSWITCH": os.getenv("BLUEFIRE_KILLSWITCH", "http://localhost:8080/kill"),
            "BLUEFIRE_SAFEMODE": os.getenv("BLUEFIRE_SAFEMODE", "0"),
            "ENCRYPT_KEY": os.getenv("ENCRYPT_KEY"),
            "SPLUNK_TOKEN": os.getenv("SPLUNK_TOKEN"),
            "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO")
        }
    
    def _load_config(self) -> None:
        """Load configuration from YAML file."""
        if not self.config_path.exists():
            self._create_default_config()
        
        with open(self.config_path, 'r') as f:
            self.config = yaml.safe_load(f)
    
    def _create_default_config(self) -> None:
        """Create default configuration file matching expected structure."""
        default_config = {
            "general": {
                "name": "BlueFire-Nexus",
                "version": "1.0.0",
                "mode": "simulation",
                "log_level": "INFO",
                "log_file": "logs/bluefire.log",
                "console_output": True,
                "safeties": {
                    "auto_wipe": True,
                    "max_runtime": 7200, # 2 hours
                    "allowed_subnets": ["10.0.0.0/8", "192.168.0.0/16"] # Example safeties
                }
            },
            "modules": {
                # Add default configurations for core modules if necessary
                "command_control": {
                    "enabled": True,
                    "default_channel": "http"
                },
                 "defense_evasion": {
                    "enabled": True,
                    "default_technique": "process_hollowing"
                },
                # ... add other modules as needed
            },
            "telemetry": {
                "enabled": False,
                "splunk": {
                    "host": "",
                    "token": "{{ env SPLUNK_TOKEN }}"
                },
                "elastic": {
                    "hosts": []
                }
            }
            # Removed lab_environment, logging, encryption sections from previous default
            # as they seem managed differently or within general/modules now.
        }

        # Ensure parent directory exists if config_path includes directories
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)
        
        self.logger.info(f"Created default configuration file at {self.config_path}")
        self.config = default_config
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key."""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value by key."""
        keys = key.split('.')
        current = self.config
        
        for k in keys[:-1]:
            current = current.setdefault(k, {})
        
        current[keys[-1]] = value
    
    def save(self) -> None:
        """Save current configuration to file."""
        with open(self.config_path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)

# Create global config instance
config = ConfigManager() 