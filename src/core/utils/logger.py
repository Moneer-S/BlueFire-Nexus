"""
Consolidated Logging Module
Provides centralized logging for all APT implementations
"""

import os
import sys
import time
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

class Logger:
    """Handles logging for all APT implementations"""
    
    # Log levels
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL
    
    def __init__(self, name: str, log_dir: str = "logs", log_level: int = logging.INFO):
        """Initialize the logger
        
        Args:
            name: The name of the logger and log file
            log_dir: The directory to store log files
            log_level: The minimum log level to record
        """
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_level = log_level
        
        # Create log directory if it doesn't exist
        self.log_dir.mkdir(exist_ok=True)
        
        # Configure logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level)
        
        # Remove any existing handlers
        if self.logger.hasHandlers():
            self.logger.handlers.clear()
        
        # Create file handler
        log_file = self.log_dir / f"{name}.log"
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)s [%(name)s] - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
    
    def debug(self, message: str) -> None:
        """Log a debug message
        
        Args:
            message: The message to log
        """
        self.logger.debug(message)
    
    def info(self, message: str) -> None:
        """Log an info message
        
        Args:
            message: The message to log
        """
        self.logger.info(message)
    
    def warning(self, message: str) -> None:
        """Log a warning message
        
        Args:
            message: The message to log
        """
        self.logger.warning(message)
    
    def error(self, message: str) -> None:
        """Log an error message
        
        Args:
            message: The message to log
        """
        self.logger.error(message)
    
    def critical(self, message: str) -> None:
        """Log a critical message
        
        Args:
            message: The message to log
        """
        self.logger.critical(message)
    
    def log_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Log a structured event
        
        Args:
            event_type: The type of event
            details: Details about the event
        """
        message = f"EVENT [{event_type}]: {details}"
        self.logger.info(message)
    
    def log_technique(self, technique: str, status: str, details: Dict[str, Any]) -> None:
        """Log a technique execution
        
        Args:
            technique: The technique being executed
            status: The status of the execution (success, failure, etc.)
            details: Details about the execution
        """
        message = f"TECHNIQUE [{technique}] {status}: {details}"
        self.logger.info(message)
    
    def log_error(self, error_type: str, message: str, exc_info: bool = False) -> None:
        """Log an error with more structured information
        
        Args:
            error_type: The type of error
            message: The error message
            exc_info: Whether to include exception information
        """
        error_message = f"ERROR [{error_type}]: {message}"
        self.logger.error(error_message, exc_info=exc_info)

# Default logger
default_logger = Logger("bluefire")

# Helper functions for module-level logging
def get_logger(name: str, log_level: int = logging.INFO) -> Logger:
    """Get a logger with the specified name
    
    Args:
        name: The name of the logger
        log_level: The minimum log level to record
    
    Returns:
        A Logger instance
    """
    return Logger(name, log_level=log_level)

def debug(message: str) -> None:
    """Log a debug message using the default logger
    
    Args:
        message: The message to log
    """
    default_logger.debug(message)

def info(message: str) -> None:
    """Log an info message using the default logger
    
    Args:
        message: The message to log
    """
    default_logger.info(message)

def warning(message: str) -> None:
    """Log a warning message using the default logger
    
    Args:
        message: The message to log
    """
    default_logger.warning(message)

def error(message: str) -> None:
    """Log an error message using the default logger
    
    Args:
        message: The message to log
    """
    default_logger.error(message)

def critical(message: str) -> None:
    """Log a critical message using the default logger
    
    Args:
        message: The message to log
    """
    default_logger.critical(message)

def log_event(event_type: str, details: Dict[str, Any]) -> None:
    """Log a structured event using the default logger
    
    Args:
        event_type: The type of event
        details: Details about the event
    """
    default_logger.log_event(event_type, details)

def log_technique(technique: str, status: str, details: Dict[str, Any]) -> None:
    """Log a technique execution using the default logger
    
    Args:
        technique: The technique being executed
        status: The status of the execution (success, failure, etc.)
        details: Details about the execution
    """
    default_logger.log_technique(technique, status, details)

def log_error(error_type: str, message: str, exc_info: bool = False) -> None:
    """Log an error with more structured information using the default logger
    
    Args:
        error_type: The type of error
        message: The error message
        exc_info: Whether to include exception information
    """
    default_logger.log_error(error_type, message, exc_info=exc_info) 