#!/usr/bin/env python3
"""
PGDN Discovery CLI

Fast multi-stage discovery tool with automatic protocol detection.
"""

import argparse
import json
import sys
import os
import logging
from typing import Dict, List, Any, Optional

from .discovery import ProtocolDiscoverer

# Configure logger for CLI
logger = logging.getLogger(__name__)


def discover_protocols(ip: str, timeout: int = 5, protocol_filter: Optional[str] = None, 
                      ai_fallback: bool = False) -> Dict[str, Any]:
    """Simple protocol discovery - returns data array or error"""
    
    logger.info(f"CLI discovery started for {ip}")
    if protocol_filter:
        logger.info(f"CLI using protocol filter: {protocol_filter}")
    
    try:
        # Run protocol discovery
        discoverer = ProtocolDiscoverer(timeout=timeout)
        discovery_result = discoverer.discover(ip, stage="all", protocol_filter=protocol_filter)
        
        # Check for errors first
        if discovery_result.errors:
            error_msg = discovery_result.errors.get("discovery", "Unknown error")
            logger.error(f"CLI discovery failed for {ip}: {error_msg}")
            return {"error": error_msg}
        
        # Extract all protocols found
        protocols = []
        if discovery_result.open_ports and discovery_result.http_responses:
            for port, paths_data in discovery_result.http_responses.items():
                for path, response_data in paths_data.items():
                    if isinstance(response_data, dict) and 'endpoint' in response_data:
                        protocol_info = {
                            "protocol": response_data["protocol"],
                            "endpoint": response_data["endpoint"]
                        }
                        protocols.append(protocol_info)
                        logger.info(f"CLI found protocol: {protocol_info}")
        
        logger.info(f"CLI discovery completed for {ip}, found {len(protocols)} protocols")
        # Always return data array (even if empty)
        return {"data": protocols}
        
    except Exception as e:
        logger.error(f"CLI discovery exception for {ip}: {str(e)}")
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
  
  # With verbose logging
  pgdn-discovery discover 192.168.1.100 --verbose
  
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
        help='Only scan for specific protocol (e.g., sui, ethereum, walrus)'
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
    discover_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'discover':
        # Configure logging based on verbosity
        if hasattr(args, 'verbose') and args.verbose:
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            logger.info("Verbose logging enabled")
        else:
            # Show INFO level messages even without verbose mode for better visibility
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        try:
            logger.info(f"Starting CLI discovery for {args.ip}")
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
                logger.error(f"CLI discovery failed with error: {result['error']}")
                sys.exit(1)
            else:
                logger.info("CLI discovery completed successfully")
                sys.exit(0)
                
        except KeyboardInterrupt:
            logger.info("CLI discovery interrupted by user")
            sys.exit(1)
        except Exception as e:
            logger.error(f"CLI discovery failed with exception: {str(e)}")
            sys.exit(1)


if __name__ == "__main__":
    main() 