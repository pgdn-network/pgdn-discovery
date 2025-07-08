#!/usr/bin/env python3
"""
PGDN Discovery CLI

Fast multi-stage discovery tool with automatic protocol detection.
"""

import argparse
import json
import sys
import os
from typing import Dict, List, Any, Optional

from .discovery import ProtocolDiscoverer


def discover_protocols(ip: str, timeout: int = 5, protocol_filter: Optional[str] = None, 
                      ai_fallback: bool = False) -> Dict[str, Any]:
    """Simple RPC-based protocol discovery - returns data array or error"""
    
    try:
        # Run simple RPC-based discovery
        discoverer = ProtocolDiscoverer(timeout=timeout)
        discovery_result = discoverer.discover(ip, stage="all", protocol_filter=protocol_filter)
        
        # Check for errors first
        if discovery_result.errors:
            return {"error": discovery_result.errors.get("discovery", "Unknown error")}
        
        # Extract all protocols found
        protocols = []
        if discovery_result.open_ports and discovery_result.http_responses:
            for port, paths_data in discovery_result.http_responses.items():
                for path, response_data in paths_data.items():
                    if isinstance(response_data, dict) and 'endpoint' in response_data:
                        protocols.append({
                            "protocol": response_data["protocol"],
                            "endpoint": response_data["endpoint"]
                        })
        
        # Always return data array (even if empty)
        return {"data": protocols}
        
    except Exception as e:
        # Return error block
        return {"error": str(e)}


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        prog='pgdn-discovery',
        description="PGDN Discovery - Fast Multi-stage Protocol Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Discover all protocols
  pgdn-discovery discover 192.168.1.100
  
  # Discover only Sui protocol
  pgdn-discovery discover 192.168.1.100 --protocol sui
  
  # With AI fallback for unknown protocols
  pgdn-discovery discover 192.168.1.100 --ai-fallback
  
  # With custom timeout
  pgdn-discovery discover 192.168.1.100 --timeout 10
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Discover command (new primary command)
    discover_parser = subparsers.add_parser('discover', help='Auto-discover protocols using signatures')
    discover_parser.add_argument('ip', help='Target IP address')
    discover_parser.add_argument(
        '--protocol',
        help='Only scan for specific protocol (e.g., sui, filecoin)'
    )
    discover_parser.add_argument(
        '--ai-fallback',
        action='store_true',
        help='Use AI detection when signature matching fails (requires API keys)'
    )
    discover_parser.add_argument(
        '--timeout',
        type=int,
        default=5,
        help='Network timeout in seconds (default: 5)'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'discover':
        try:
            # Run discovery
            result = discover_protocols(
                args.ip, 
                timeout=args.timeout,
                protocol_filter=args.protocol,
                ai_fallback=args.ai_fallback
            )
            
            # Output result (no pretty printing)
            print(json.dumps(result))
            
            # Exit with error code only if there's an error
            if "error" in result:
                sys.exit(1)
            else:
                sys.exit(0)
                
        except KeyboardInterrupt:
            sys.exit(1)
        except Exception as e:
            sys.exit(1)


if __name__ == "__main__":
    main() 