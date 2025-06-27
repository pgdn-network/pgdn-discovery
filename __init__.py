"""
PGDN Discovery - Professional DePIN Protocol Discovery Library

A comprehensive library for discovering DePIN protocols on network nodes
with configurable discovery methods and analysis tools.

Usage Examples:

# Quick discovery
from pgdn_discovery import discover_node
result = discover_node("192.168.1.100")

# Professional discovery client
from pgdn_discovery import create_discovery_client
client = create_discovery_client(timeout=60, debug=True)
result = client.run_discovery(
    target='192.168.1.100',
    enabled_methods=['probe', 'ai'],
    enabled_tools=['nmap', 'http_client']
)

# Targeted probe discovery
result = client.run_probe_discovery(
    target='192.168.1.100',
    probes=[{"port": 9000, "path": "/metrics"}],
    include_ai=True
)

# DePIN protocol discovery
result = client.discover_depin_protocols('192.168.1.100')
"""

from .lib.discovery_client import PGDNDiscovery, DiscoveryResult, create_discovery_client, discover_node

# Legacy compatibility
from .lib.discovery import discover_node as legacy_discover_node

__version__ = "1.0.0"
__all__ = [
    "PGDNDiscovery", 
    "DiscoveryResult", 
    "create_discovery_client", 
    "discover_node",
    "legacy_discover_node"
]
