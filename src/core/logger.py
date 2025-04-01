import logging
import sys
from pathlib import Path
from rich.logging import RichHandler
from datetime import datetime

def setup_logger(name: str = "bluefire", log_level: str = "INFO") -> logging.Logger:
    """
    Set up a logger with both file and console handlers.
    
    Args:
        name (str): Name of the logger
        log_level (str): Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    
    Returns:
        logging.Logger: Configured logger instance
    """
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Create formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # File handler
    log_file = log_dir / f"bluefire_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Console handler with rich formatting
    console_handler = RichHandler(rich_tracebacks=True)
    logger.addHandler(console_handler)
    
    return logger

# Create default logger instance
logger = setup_logger()

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the specified name.
    
    Args:
        name (str): Name of the logger
    
    Returns:
        logging.Logger: Logger instance
    """
    return logging.getLogger(f"bluefire.{name}") 