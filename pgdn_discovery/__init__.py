"""
PGDN Discovery - Modular Staged Probing Pipeline

A clean, modular library for network probing with staged discovery.
"""

from .discovery import discover_node, NetworkProber, DiscoveryResult, COMMON_PORTS, COMMON_ENDPOINTS

__version__ = "0.1.1"
__all__ = ["discover_node", "NetworkProber", "DiscoveryResult", "COMMON_PORTS", "COMMON_ENDPOINTS"]

# CLI entry point
def main():
    """Entry point for the CLI"""
    import sys
    import os
    # Add the parent directory to the path so we can import cli
    parent_dir = os.path.dirname(os.path.dirname(__file__))
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    
    from cli import main as cli_main
    cli_main()
