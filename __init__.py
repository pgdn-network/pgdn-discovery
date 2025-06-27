"""
PGDN Discovery - Simple DePIN Protocol Discovery Library

A lightweight library for discovering DePIN protocols on network nodes.
Can be used both as a CLI tool and as a Python library.

CLI Usage:
    pgdn-discovery --help
    pgdn-discovery 192.168.1.100
    pgdn-discovery example.com --json

Library Usage:
    from pgdn_discovery import discover_node, create_discovery_client
    
    # Simple usage
    result = discover_node("192.168.1.100")
    
    # Reusable client
    client = create_discovery_client(timeout=60)
    result = client.discover_node("192.168.1.100")
"""

from .pgdn_discovery import discover_node, create_discovery_client

__version__ = "0.1.0"
__all__ = ["discover_node", "create_discovery_client"]
