#!/usr/bin/env python3
"""
PGDN Discovery CLI

Command-line interface for the modular staged probing pipeline.
"""

import argparse
import json
import sys
from typing import List, Optional

from lib.discovery import discover_node, COMMON_PORTS, COMMON_ENDPOINTS


def parse_csv_ints(csv_string: str) -> List[int]:
    """Parse comma-separated integers"""
    if not csv_string:
        return []
    try:
        return [int(x.strip()) for x in csv_string.split(',')]
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid port list: {e}")


def parse_csv_strings(csv_string: str) -> List[str]:
    """Parse comma-separated strings"""
    if not csv_string:
        return []
    return [x.strip() for x in csv_string.split(',')]


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        prog='pgdn-discovery',
        description="PGDN Discovery - Modular Network Probing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pgdn-discovery discover 192.168.1.100
  pgdn-discovery discover 192.168.1.100 --stage 1
  pgdn-discovery discover 192.168.1.100 --stage 1 --ports 80,443,9000
  pgdn-discovery discover 192.168.1.100 --stage 2 --ports 80,443 --paths /,/metrics
  pgdn-discovery discover 192.168.1.100 --stage all --ports 80,443 --paths /,/rpc/v0,/status
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Discover command
    discover_parser = subparsers.add_parser('discover', help='Run network discovery')
    discover_parser.add_argument('ip', help='Target IP address')
    discover_parser.add_argument(
        '--stage', 
        choices=['1', '2', 'all'], 
        default='all',
        help='Discovery stage: 1=port scan, 2=web scan, all=both (default: all)'
    )
    discover_parser.add_argument(
        '--ports',
        type=parse_csv_ints,
        help=f'Comma-separated list of ports (default: {",".join(map(str, COMMON_PORTS))})'
    )
    discover_parser.add_argument(
        '--paths',
        type=parse_csv_strings,
        help=f'Comma-separated list of HTTP paths (default: {",".join(COMMON_ENDPOINTS)})'
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
            # Run discovery with provided arguments
            result = discover_node(
                ip=args.ip,
                stage=args.stage,
                ports=args.ports,  # Will use defaults if None
                paths=args.paths,  # Will use defaults if None
                timeout=args.timeout
            )
            
            # Print JSON output to stdout
            print(json.dumps(result, indent=2))
            
        except KeyboardInterrupt:
            print(json.dumps({"error": "Discovery cancelled by user"}), file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(json.dumps({"error": str(e)}), file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main() 