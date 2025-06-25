"""
Logging configuration for PGDN Discovery

Provides centralized logging setup for the discovery library.
"""

import logging
import sys
from typing import Optional


def setup_logging(level: str = "INFO", debug: bool = False) -> logging.Logger:
    """
    Setup logging configuration for PGDN Discovery.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        debug: Enable debug output
        
    Returns:
        Configured logger instance
    """
    # Convert string level to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # Configure root logger
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Get logger for PGDN
    logger = logging.getLogger('pgdn_discovery')
    
    if debug:
        logger.setLevel(logging.DEBUG)
    
    return logger


def get_logger(name: str = 'pgdn_discovery') -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)
