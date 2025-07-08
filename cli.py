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

from pgdn_discovery.discovery import NetworkProber


def discover_protocols(ip: str, timeout: int = 5, protocol_filter: Optional[str] = None, 
                      ai_fallback: bool = False) -> Optional[Dict[str, str]]:
    """Simple RPC-based protocol discovery - returns only successful results"""
    
    try:
        # Run simple RPC-based discovery
        prober = NetworkProber(timeout=timeout)
        discovery_result = prober.discover(ip, stage="all", protocol_filter=protocol_filter)
        
        # Only return successful results
        if discovery_result.open_ports and discovery_result.http_responses:
            for port, paths_data in discovery_result.http_responses.items():
                for path, response_data in paths_data.items():
                    if isinstance(response_data, dict) and 'endpoint' in response_data:
                        # SUCCESS: Return simple result
                        return {
                            "protocol": response_data["protocol"],
                            "endpoint": response_data["endpoint"]
                        }
        
        # No successful results - return None
        return None
        
    except Exception:
        # Silent failure - return None
        return None


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
            
            # Output result
            if result:
                print(json.dumps(result, indent=2))
                sys.exit(0)
            else:
                # No results found - exit with error code
                sys.exit(1)
                
        except KeyboardInterrupt:
            sys.exit(1)
        except Exception as e:
            sys.exit(1)


if __name__ == "__main__":
    main() 