#!/usr/bin/env python3
"""
PGDN Discovery CLI

Two-stage discovery tool that accepts JSON protocol definitions
and probes specific port/path combinations.
"""

import argparse
import json
import sys
from typing import Dict, List, Any, Optional

from pgdn_discovery.discovery_components.probe_scanner import ProbeScanner


def parse_input_json(input_data: str) -> List[Dict[str, Any]]:
    """Parse input JSON protocol definitions"""
    try:
        data = json.loads(input_data)
        if not isinstance(data, list):
            raise ValueError("Input must be a JSON array of protocol definitions")
        return data
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON input: {e}")


def validate_protocol_definition(protocol_def: Dict[str, Any]) -> bool:
    """Validate a protocol definition structure"""
    if not isinstance(protocol_def, dict):
        return False
    
    if 'protocol' not in protocol_def or 'results' not in protocol_def:
        return False
    
    if not isinstance(protocol_def['results'], list):
        return False
    
    for result in protocol_def['results']:
        if not isinstance(result, dict):
            return False
        if 'port' not in result or 'path' not in result:
            return False
    
    return True


def process_protocols(ip: str, protocols: List[Dict[str, Any]], timeout: int = 5) -> Dict[str, Any]:
    """Process protocol definitions and return structured results"""
    
    # Validate all protocol definitions
    for protocol_def in protocols:
        if not validate_protocol_definition(protocol_def):
            return {
                "data": [],
                "error": f"Invalid protocol definition: {protocol_def}",
                "meta": {
                    "protocols_attempted": 0,
                    "total_successful_probes": 0
                },
                "result_type": "error"
            }
    
    scanner = ProbeScanner(timeout=timeout)
    
    # Prepare probes list
    all_probes = []
    for protocol_def in protocols:
        for result in protocol_def['results']:
            probe = {
                'protocol': protocol_def['protocol'],
                'port': result['port'],
                'path': result['path']
            }
            # Include expected body if provided (for validation)
            if 'body' in result:
                probe['expected_body'] = result['body']
            all_probes.append(probe)
    
    try:
        # Run the probe scanner
        probe_result = scanner.probe_services(ip, all_probes)
        
        if probe_result.error:
            return {
                "data": [],
                "error": probe_result.error,
                "meta": {
                    "protocols_attempted": len(protocols),
                    "total_successful_probes": 0
                },
                "result_type": "error"
            }
        
        # Group results by protocol
        protocol_results = {}
        
        for i, probe_data in enumerate(probe_result.data):
            protocol_name = all_probes[i]['protocol']
            
            if protocol_name not in protocol_results:
                protocol_results[protocol_name] = {
                    "protocol": protocol_name,
                    "results": []
                }
            
            # Build result entry
            result_entry = {
                "port": probe_data.port,
                "path": probe_data.path,
                "status_code": probe_data.status_code,
                "headers": probe_data.headers,
                "body": probe_data.body,
                "tls_info": probe_data.tls_info
            }
            
            # Add error if present
            if probe_data.error:
                result_entry["error"] = probe_data.error
            
            protocol_results[protocol_name]["results"].append(result_entry)
        
        # Convert to list format
        data = list(protocol_results.values())
        
        # Use ProbeScanner's accurate count: successful = total - failed
        total_probes = probe_result.meta.get("probe_count", len(all_probes))
        failed_probes = probe_result.meta.get("failed", 0)
        successful_probes = total_probes - failed_probes
        
        return {
            "data": data,
            "error": None,
            "meta": {
                "protocols_attempted": len(protocols),
                "total_successful_probes": successful_probes
            },
            "result_type": "success"
        }
        
    except Exception as e:
        return {
            "data": [],
            "error": str(e),
            "meta": {
                "protocols_attempted": len(protocols),
                "total_successful_probes": 0
            },
            "result_type": "error"
        }


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        prog='pgdn-discovery',
        description="PGDN Discovery - Two-stage Protocol Probing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # From file
  pgdn-discovery probe 192.168.1.100 --input protocols.json
  
  # From stdin
  echo '[{"protocol":"sui","results":[{"port":9000,"path":"/metrics"}]}]' | pgdn-discovery probe 192.168.1.100
  
  # With custom timeout
  pgdn-discovery probe 192.168.1.100 --input protocols.json --timeout 10

Input JSON format:
[
  {
    "protocol": "sui",
    "results": [
      {
        "port": 9000,
        "path": "/metrics"
      }
    ]
  }
]
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Probe command
    probe_parser = subparsers.add_parser('probe', help='Run protocol probing')
    probe_parser.add_argument('ip', help='Target IP address')
    probe_parser.add_argument(
        '--input', '-i',
        help='Input JSON file with protocol definitions (use "-" for stdin)'
    )
    probe_parser.add_argument(
        '--timeout',
        type=int,
        default=5,
        help='Network timeout in seconds (default: 5)'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'probe':
        try:
            # Read input JSON
            if args.input:
                if args.input == '-':
                    input_data = sys.stdin.read()
                else:
                    with open(args.input, 'r') as f:
                        input_data = f.read()
            else:
                # Try reading from stdin
                if not sys.stdin.isatty():
                    input_data = sys.stdin.read()
                else:
                    print(json.dumps({
                        "data": [],
                        "error": "No input provided. Use --input file.json or pipe JSON to stdin",
                        "meta": {"protocols_attempted": 0, "total_successful_probes": 0},
                        "result_type": "error"
                    }), file=sys.stderr)
                    sys.exit(1)
            
            # Parse protocol definitions
            protocols = parse_input_json(input_data.strip())
            
            # Process protocols
            result = process_protocols(args.ip, protocols, args.timeout)
            
            # Output result
            print(json.dumps(result, indent=2))
            
            # Exit with error code if result_type is error
            if result.get("result_type") == "error":
                sys.exit(1)
                
        except KeyboardInterrupt:
            print(json.dumps({
                "data": [],
                "error": "Probing cancelled by user",
                "meta": {"protocols_attempted": 0, "total_successful_probes": 0},
                "result_type": "error"
            }), file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(json.dumps({
                "data": [],
                "error": str(e),
                "meta": {"protocols_attempted": 0, "total_successful_probes": 0},
                "result_type": "error"
            }), file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main() 