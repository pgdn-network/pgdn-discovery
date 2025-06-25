"""
Entry point for the PGDN Discover console script.
"""

import sys
import os

# Add the current directory to the Python path so we can import main
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli import main

if __name__ == "__main__":
    main()
