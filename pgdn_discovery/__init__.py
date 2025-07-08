"""
PGDN Discovery - Modular Staged Probing Pipeline

A clean, modular library for network probing with staged discovery.
"""

from .discovery import discover_node, NetworkProber, DiscoveryResult

__version__ = "0.1.1"
__all__ = ["discover_node", "NetworkProber", "DiscoveryResult"]

# CLI entry point
def main():
    """Entry point for the CLI"""
    from .cli import main as cli_main
    cli_main()
