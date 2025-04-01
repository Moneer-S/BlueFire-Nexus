"""
BlueFire Nexus - Main Entry Point
Consolidated APT Simulation Framework
"""

import os
import sys
import json
import argparse
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

# Import core modules
from core.utils import logger
from core.reconnaissance.reconnaissance import ReconnaissanceManager
from core.access.initial_access import InitialAccessManager
from core.execution.execution import ExecutionManager
from core.persistence.persistence import PersistenceManager
from core.evasion.defense_evasion import DefenseEvasionManager
from core.command.command_control import CommandControlManager
from core.resource.resource_development import ResourceDevelopmentManager

class BlueFire:
    """Main BlueFire Nexus Framework Class"""
    
    def __init__(self, config_path: Optional[str] = None, log_level: int = logger.INFO):
        """Initialize the BlueFire framework
        
        Args:
            config_path: Path to the configuration file
            log_level: Logging level
        """
        # Initialize logger
        self.log = logger.get_logger("bluefire", log_level=log_level)
        self.log.info("Initializing BlueFire Nexus Framework")
        
        # Load configuration
        self.config = self._load_config(config_path)
        self.log.info(f"Loaded configuration: {len(self.config.keys())} sections")
        
        # Initialize modules
        self.log.info("Initializing modules")
        self.recon = ReconnaissanceManager()
        self.access = InitialAccessManager()
        self.execution = ExecutionManager()
        self.persistence = PersistenceManager()
        self.evasion = DefenseEvasionManager()
        self.command = CommandControlManager()
        self.resource = ResourceDevelopmentManager()
        self.log.info("All modules initialized successfully")
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            Configuration dictionary
        """
        default_config = {
            "general": {
                "name": "BlueFire Nexus",
                "version": "1.0.0",
                "description": "Advanced APT Simulation Framework",
                "mode": "simulation"
            },
            "techniques": {
                "reconnaissance": True,
                "initial_access": True,
                "execution": True,
                "persistence": True,
                "defense_evasion": True,
                "command_control": True,
                "resource_development": True
            },
            "logging": {
                "level": "INFO",
                "file": "bluefire.log",
                "console": True
            }
        }
        
        if not config_path:
            self.log.info("No configuration file provided, using default configuration")
            return default_config
        
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                self.log.info(f"Configuration loaded from {config_path}")
                return config
        except Exception as e:
            self.log.error(f"Error loading configuration from {config_path}: {str(e)}")
            self.log.warning("Using default configuration instead")
            return default_config
    
    def run(self, operation: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Run a specific operation
        
        Args:
            operation: Name of the operation to run
            data: Data for the operation
            
        Returns:
            Result of the operation
        """
        self.log.info(f"Running operation: {operation}")
        result = {"status": "error", "message": f"Unknown operation: {operation}"}
        
        try:
            if operation == "reconnaissance":
                self.log.log_technique("reconnaissance", "starting", data)
                result = self.recon.recon(data)
                self.log.log_technique("reconnaissance", "completed", {"status": "success"})
            
            elif operation == "initial_access":
                self.log.log_technique("initial_access", "starting", data)
                result = self.access.access(data)
                self.log.log_technique("initial_access", "completed", {"status": "success"})
            
            elif operation == "execution":
                self.log.log_technique("execution", "starting", data)
                result = self.execution.execute(data)
                self.log.log_technique("execution", "completed", {"status": "success"})
            
            elif operation == "persistence":
                self.log.log_technique("persistence", "starting", data)
                result = self.persistence.persist(data)
                self.log.log_technique("persistence", "completed", {"status": "success"})
            
            elif operation == "defense_evasion":
                self.log.log_technique("defense_evasion", "starting", data)
                result = self.evasion.evade(data)
                self.log.log_technique("defense_evasion", "completed", {"status": "success"})
            
            elif operation == "command_control":
                self.log.log_technique("command_control", "starting", data)
                result = self.command.control(data)
                self.log.log_technique("command_control", "completed", {"status": "success"})
            
            elif operation == "resource_development":
                self.log.log_technique("resource_development", "starting", data)
                result = self.resource.develop(data)
                self.log.log_technique("resource_development", "completed", {"status": "success"})
            
            else:
                self.log.error(f"Unknown operation: {operation}")
                result = {"status": "error", "message": f"Unknown operation: {operation}"}
            
            return result
        
        except Exception as e:
            self.log.log_error("operation", f"Error running operation {operation}: {str(e)}", exc_info=True)
            return {"status": "error", "message": str(e)}
    
    def run_campaign(self, campaign_config: Dict[str, Any]) -> Dict[str, Any]:
        """Run a full campaign with multiple operations
        
        Args:
            campaign_config: Campaign configuration
            
        Returns:
            Results of the campaign
        """
        self.log.info(f"Starting campaign: {campaign_config.get('name', 'Unnamed')}")
        results = {
            "campaign": campaign_config.get('name', 'Unnamed'),
            "timestamp": datetime.now().isoformat(),
            "operations": [],
            "status": "success"
        }
        
        try:
            # Extract operations from campaign config
            operations = campaign_config.get('operations', [])
            self.log.info(f"Campaign contains {len(operations)} operations")
            
            # Run each operation in sequence
            for op in operations:
                operation = op.get('operation')
                data = op.get('data', {})
                
                self.log.info(f"Running campaign operation: {operation}")
                result = self.run(operation, data)
                
                # Store the result
                results['operations'].append({
                    "operation": operation,
                    "result": result
                })
                
                # Stop campaign if operation failed and fail_fast is enabled
                if result.get('status') == 'error' and campaign_config.get('fail_fast', False):
                    self.log.warning(f"Campaign stopping due to failed operation: {operation}")
                    results['status'] = 'error'
                    results['message'] = f"Campaign stopped due to failed operation: {operation}"
                    break
            
            self.log.info(f"Campaign completed with status: {results['status']}")
            return results
        
        except Exception as e:
            self.log.log_error("campaign", f"Error running campaign: {str(e)}", exc_info=True)
            results['status'] = 'error'
            results['message'] = str(e)
            return results

def main():
    """Main function for CLI operation"""
    parser = argparse.ArgumentParser(description="BlueFire Nexus - Advanced APT Simulation Framework")
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--operation', help='Operation to run')
    parser.add_argument('--data', help='JSON data for the operation')
    parser.add_argument('--campaign', help='Path to campaign configuration file')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], 
                        default='INFO', help='Logging level')
    
    args = parser.parse_args()
    
    # Set up logging level
    log_level = getattr(logger, args.log_level)
    
    # Initialize BlueFire
    bluefire = BlueFire(args.config, log_level)
    
    # Run campaign or single operation
    if args.campaign:
        try:
            with open(args.campaign, 'r') as f:
                campaign_config = json.load(f)
            results = bluefire.run_campaign(campaign_config)
            print(json.dumps(results, indent=2))
        except Exception as e:
            logger.critical(f"Error running campaign: {str(e)}")
            sys.exit(1)
    
    elif args.operation:
        try:
            data = {}
            if args.data:
                data = json.loads(args.data)
            results = bluefire.run(args.operation, data)
            print(json.dumps(results, indent=2))
        except Exception as e:
            logger.critical(f"Error running operation: {str(e)}")
            sys.exit(1)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 