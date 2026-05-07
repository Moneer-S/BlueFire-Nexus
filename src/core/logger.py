import logging
import os
from datetime import datetime
from pathlib import Path

from rich.logging import RichHandler


def _resolve_log_dir() -> Path:
    """Resolve the directory the file handler writes to.

    Honours the ``BLUEFIRE_LOG_DIR`` env var so tests (and containers
    that mount a writable volume) can redirect logs away from the
    project root. Mirrors the way ``BLUEFIRE_OUTPUT_ROOT`` redirects
    the runtime output_root via ``core.configuration.resolve_output_root``.
    Falls back to ``logs/`` under the current working directory when
    the env var is unset, preserving the prior behaviour for normal
    runtime use.
    """
    env_dir = os.environ.get("BLUEFIRE_LOG_DIR", "").strip()
    return Path(env_dir) if env_dir else Path("logs")


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
    log_dir = _resolve_log_dir()
    log_dir.mkdir(parents=True, exist_ok=True)

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
