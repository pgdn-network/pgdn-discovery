"""
PGDN Discovery - Modular Staged Probing Pipeline

A clean, modular library for network probing with staged discovery.
"""

from .discovery import discover_node, NetworkProber, DiscoveryResult, COMMON_PORTS, COMMON_ENDPOINTS

__version__ = "0.1.0"
__all__ = ["discover_node", "NetworkProber", "DiscoveryResult", "COMMON_PORTS", "COMMON_ENDPOINTS"]
