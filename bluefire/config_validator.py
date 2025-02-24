# src/bluefire/config_validator.py
import yaml
import logging
from typing import Any, Dict

class ConfigValidator:
    """
    Validates the configuration file for BlueFire-Nexus against a predefined schema.
    """
    SCHEMA = {
        "lab_environment": {
            "network": str,
            "allowed_hosts": list,
        },
        "safeties": {
            "auto_wipe": str,  # should be 'enabled' or 'disabled'
            "max_runtime": int,
        }
    }
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.logger = logging.getLogger(__name__)
    
    def load_config(self) -> Dict[str, Any]:
        self.logger.debug("Loading configuration from %s", self.config_path)
        try:
            with open(self.config_path, "r") as file:
                config = yaml.safe_load(file)
        except Exception as e:
            self.logger.error("Error loading configuration: %s", e)
            raise
        self.logger.info("Configuration loaded successfully.")
        return config
    
    def validate(self, config: Dict[str, Any]) -> bool:
        """
        Validates the configuration dictionary against the schema.
        
        Raises:
            ValueError: If the configuration does not conform to the schema.
        """
        for section, rules in self.SCHEMA.items():
            if section not in config:
                raise ValueError(f"Missing required section: {section}")
            section_data = config[section]
            for key, expected_type in rules.items():
                if key not in section_data:
                    raise ValueError(f"Missing key '{key}' in section '{section}'")
                value = section_data[key]
                if not isinstance(value, expected_type):
                    raise ValueError(f"Incorrect type for '{key}' in section '{section}': Expected {expected_type.__name__}, got {type(value).__name__}")
                # Additional specific validations
                if section == "safeties" and key == "auto_wipe":
                    if value not in ("enabled", "disabled"):
                        raise ValueError(f"Invalid value for 'auto_wipe': Expected 'enabled' or 'disabled', got '{value}'")
                if section == "safeties" and key == "max_runtime":
                    if value <= 0:
                        raise ValueError(f"Invalid value for 'max_runtime': Must be a positive integer, got {value}")
                if section == "lab_environment" and key == "allowed_hosts":
                    if not all(isinstance(host, str) for host in value):
                        raise ValueError("All items in 'allowed_hosts' must be strings.")
        
        self.logger.info("Configuration validated successfully.")
        return True

# Example usage:
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    validator = ConfigValidator("config.yaml")
    try:
        config = validator.load_config()
        validator.validate(config)
        print("Configuration is valid.")
    except Exception as e:
        print(f"Configuration error: {e}")
