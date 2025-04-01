from .command_control.command_control import CommandControl
from .initial_access.initial_access import InitialAccess
from .defense_evasion.defense_evasion import DefenseEvasion
from .anti_detection.anti_detection import AntiDetection
from .discovery.discovery import Discovery
from .intelligence.apt_intelligence import APTIntelligence
from .network.network_obfuscator import NetworkObfuscator
from .resource.resource_development import ResourceDevelopment
from .reconnaissance.reconnaissance import Reconnaissance
from .exfiltration.exfiltration import Exfiltration
from .persistence.persistence import Persistence
from .execution.execution import Execution
import logging
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

class BlueFireNexus:
    """Main class for the BlueFire-Nexus APT simulation platform."""
    
    def __init__(self, config_path: Optional[str] = None):
        # Setup logger first
        self.logger = logging.getLogger(__name__)
        # Basic config for logger until file config is loaded
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        self.config_path = config_path or self._find_config()
        self.config = self._load_config()
        
        # Initialize modules in dependency order
        self.execution = Execution()
        # CommandControl needed for Exfil via C2
        self.command_control = CommandControl(nexus_instance=self) 
        self.persistence = Persistence(execution_module=self.execution)
        self.defense_evasion = DefenseEvasion(execution_module=self.execution)
        self.exfiltration = Exfiltration(command_control_module=self.command_control)
        self.initial_access = InitialAccess()
        self.anti_detection = AntiDetection()
        self.discovery = Discovery()
        self.apt_intelligence = APTIntelligence()
        self.network_obfuscator = NetworkObfuscator()
        self.resource_development = ResourceDevelopment()
        self.reconnaissance = Reconnaissance()
        
        self.MODULE_MAP = {
            "command_control": self.command_control,
            "initial_access": self.initial_access,
            "defense_evasion": self.defense_evasion,
            "anti_detection": self.anti_detection,
            "discovery": self.discovery,
            "intelligence": self.apt_intelligence,
            "network_obfuscator": self.network_obfuscator,
            "resource_development": self.resource_development,
            "reconnaissance": self.reconnaissance,
            "exfiltration": self.exfiltration,
            "persistence": self.persistence,
            "execution": self.execution
        }
        
        self._configure_modules() # Configure all modules after initialization
        self.logger.info("BlueFire-Nexus platform initialized.")

    def _find_config(self) -> str:
        """Find the configuration file."""
        # Prioritize config.yaml in the current directory, then search other paths
        primary_config_path = Path('config.yaml')
        if primary_config_path.exists():
            self.logger.info(f"Configuration file found at: {primary_config_path.resolve()}")
            return str(primary_config_path.resolve())
            
        # Fallback search logic (can be simplified or adapted based on project structure)
        search_paths = [Path('.'), Path('..')] # Example search paths
        secondary_config_name = 'config/config.yaml' # Less preferred path

        for base_path in search_paths:
            p = base_path / secondary_config_name
            if p.exists():
                self.logger.warning(f"Primary config.yaml not found. Using secondary config at: {p.resolve()}")
                return str(p.resolve())

        self.logger.warning(f"Configuration file not found in standard locations. Attempting to use default path: {primary_config_path}")
        # Default to primary path; ConfigManager might create it.
        return str(primary_config_path.resolve())

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        if not Path(self.config_path).exists():
            self.logger.error(f"Configuration file not found at specified path: {self.config_path}")
            return {"general": {}, "modules": {}} # Return default structure
            
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            if not config: # Handle empty config file
                 self.logger.warning(f"Configuration file {self.config_path} is empty.")
                 return {"general": {}, "modules": {}}
                 
            # Validate basic structure
            if not isinstance(config.get('general'), dict):
                self.logger.warning("Missing or invalid 'general' section in config.")
                config['general'] = {}
            if not isinstance(config.get('modules'), dict):
                self.logger.warning("Missing or invalid 'modules' section in config.")
                config['modules'] = {}
            
            # Set log level based on config BEFORE logging further
            log_level_str = config.get('general', {}).get('log_level', 'INFO').upper()
            log_level = getattr(logging, log_level_str, logging.INFO)
            # Configure root logger - consider more advanced logging setup later (file handler, rotation, etc.)
            logging.getLogger().setLevel(log_level) 
            self.logger.info(f"Configuration loaded from {self.config_path}. Log level set to {log_level_str}")
            
            return config
        except yaml.YAMLError as e:
            self.logger.error(f"Error parsing configuration file {self.config_path}: {e}", exc_info=True)
            return {"general": {}, "modules": {}} # Return default structure on error
        except Exception as e:
            self.logger.error(f"Error loading configuration from {self.config_path}: {e}", exc_info=True)
            return {"general": {}, "modules": {}} # Return default structure on error
            
    def _configure_modules(self):
        """Pass relevant config sections to each module."""
        module_configs = self.config.get("modules", {})
        for name, module_instance in self.MODULE_MAP.items():
            if hasattr(module_instance, 'update_config') and callable(getattr(module_instance, 'update_config')):
                module_specific_config = module_configs.get(name, {})
                try:
                    # Pass the entire config dictionary, allowing modules to access general settings if needed
                    # Modules should still primarily use their own section via config.get(module_name, {})
                    module_instance.update_config(self.config) 
                    self.logger.debug(f"Configured module: {name}")
                except Exception as e:
                    self.logger.error(f"Error configuring module {name}: {e}", exc_info=True)
            else:
                 self.logger.warning(f"Module {name} does not have an 'update_config' method.")

    def execute_operation(self, module_name: str, operation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific operation within a chosen module."""
        if module_name not in self.MODULE_MAP:
            self.logger.error(f"Invalid module name: {module_name}")
            return {"status": "error", "message": f"Module {module_name} not found."}
        
        module_instance = self.MODULE_MAP[module_name]
        # Shallow copy to avoid modifying original input dict within module?
        data_to_pass = operation_data.copy() 
        self.logger.info(f"Executing operation in module: {module_name} with data: {data_to_pass}")
        
        try:
            # Standardized execution methods
            if module_name == "execution" and hasattr(module_instance, 'execute'):
                result = module_instance.execute(data_to_pass)
            elif module_name == "discovery" and hasattr(module_instance, 'discover'):
                result = module_instance.discover(data_to_pass)
            elif module_name == "persistence" and hasattr(module_instance, 'establish_persistence'):
                result = module_instance.establish_persistence(data_to_pass)
            elif module_name == "command_control" and hasattr(module_instance, 'run_operation'):
                result = module_instance.run_operation(data_to_pass)
            elif module_name == "defense_evasion" and hasattr(module_instance, 'run_evasion'):
                result = module_instance.run_evasion(data_to_pass)
            elif module_name == "exfiltration" and hasattr(module_instance, 'run_exfiltration'):
                result = module_instance.run_exfiltration(data_to_pass)
            # Add elif checks for standardized methods of other modules here
            # elif module_name == "initial_access" and hasattr(module_instance, 'run_operation'):
            #     result = module_instance.run_operation(data_to_pass)
            
            # Fallback/Legacy check (consider removing or refining)
            # elif hasattr(module_instance, 'run_operation'): # Generic fallback?
            #      result = module_instance.run_operation(data_to_pass)
            else:
                 # If no standard method matches, try the old handler lookup (less ideal)
                 handler_technique = list(data_to_pass.keys())[0] if data_to_pass else "default" # Assuming top-level key is technique
                 handler_name = "_handle_" + handler_technique
                 if hasattr(module_instance, handler_name) and callable(getattr(module_instance, handler_name)):
                      self.logger.warning(f"Using legacy handler lookup for {module_name}.{handler_name}. Consider standardizing module execution methods.")
                      handler = getattr(module_instance, handler_name)
                      # Pass only the nested data for the technique
                      result = handler(data_to_pass.get(handler_technique, {}))
                 else:
                      raise NotImplementedError(f"Module {module_name} does not have a standard execution method or matching legacy handler for data keys: {list(data_to_pass.keys())}")
                      
            self.logger.info(f"Operation completed in module {module_name}. Status: {result.get('status')}")
            return result
        except Exception as e:
            self.logger.error(f"Error during operation execution in module {module_name}: {e}", exc_info=True)
            return {"status": "error", "message": str(e), "module": module_name}

    def configure_module(self, module_name: str, config_data: Dict[str, Any]):
        """Dynamically update configuration for a specific module (use with caution)."""
        if module_name not in self.MODULE_MAP:
            self.logger.error(f"Cannot configure unknown module: {module_name}")
            return
            
        module_instance = self.MODULE_MAP[module_name]
        if hasattr(module_instance, 'update_config'):
            try:
                # Update the main config dict and then re-call the module's update_config
                if 'modules' not in self.config: self.config['modules'] = {}
                if module_name not in self.config['modules']: self.config['modules'][module_name] = {}
                self.config['modules'][module_name].update(config_data)
                
                # Re-pass the entire updated config to the module
                module_instance.update_config(self.config)
                self.logger.info(f"Dynamically reconfigured module: {module_name}")
            except Exception as e:
                self.logger.error(f"Error dynamically configuring module {module_name}: {e}", exc_info=True)
        else:
            self.logger.warning(f"Module {module_name} cannot be dynamically configured (no update_config method).")

    def reload_config(self):
        """Reload configuration from the config file."""
        self.logger.info(f"Reloading configuration from {self.config_path}")
        self.config = self._load_config()
        self._configure_modules() # Reconfigure all modules with new config
        self.logger.info("Configuration reloaded and modules reconfigured.") 