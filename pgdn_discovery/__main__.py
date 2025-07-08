#!/usr/bin/env python3
"""
PGDN Discovery CLI - Main entry point for module execution
"""

import sys
import os

# Add the parent directory to the Python path to enable absolute imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from pgdn_discovery.cli import main
except ImportError:
    # Fallback for development/local execution
    from cli import main

if __name__ == "__main__":
    main()