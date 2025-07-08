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
from pgdn_discovery.discovery_components.protocol_signatures import ProtocolSignatureMatcher
from pgdn_discovery.discovery_components.ai_detector import AIServiceDetector


def get_all_ports_and_paths_from_signatures(signature_matcher: ProtocolSignatureMatcher, 
                                           protocol_filter: Optional[str] = None) -> tuple[List[int], List[str]]:
    """Extract all ports and paths from loaded protocol signatures"""
    all_ports = set()
    all_paths = set()
    
    for protocol_name, signature in signature_matcher.protocol_signatures.items():
        # Apply protocol filter if specified
        if protocol_filter and protocol_name != protocol_filter:
            continue
            
        all_ports.update(signature.ports)
        all_paths.update(signature.paths)
    
    return sorted(list(all_ports)), sorted(list(all_paths))


def discover_protocols(ip: str, timeout: int = 5, protocol_filter: Optional[str] = None, 
                      ai_fallback: bool = False) -> Dict[str, Any]:
    """Discover protocols using fast multi-stage discovery with signature matching"""
    
    try:
        # Load signature matcher
        signature_matcher = ProtocolSignatureMatcher()
        
        if not signature_matcher.protocol_signatures:
            return {
                "data": [],
                "error": "No protocol signatures loaded",
                "meta": {"protocols_available": 0, "open_ports": 0},
                "result_type": "error"
            }
        
        # Get all ports and paths from signatures
        ports, paths = get_all_ports_and_paths_from_signatures(signature_matcher, protocol_filter)
        
        if not ports:
            return {
                "data": [],
                "error": f"No ports found for protocol filter: {protocol_filter}" if protocol_filter else "No ports found in signatures",
                "meta": {"protocols_available": len(signature_matcher.protocol_signatures), "open_ports": 0},
                "result_type": "error"
            }
        
        # Run fast discovery
        prober = NetworkProber(timeout=timeout)
        discovery_result = prober.discover(ip, stage="all", ports=ports, paths=paths)
        
        if not discovery_result.open_ports:
            return {
                "data": [],
                "error": None,
                "meta": {
                    "protocols_available": len(signature_matcher.protocol_signatures),
                    "open_ports": 0,
                    "scanned_ports": len(ports),
                    "duration_seconds": discovery_result.duration_seconds
                },
                "result_type": "no_open_ports"
            }
        
        # Convert HTTP responses to probe format for signature matching
        probe_results = []
        for port, paths_data in discovery_result.http_responses.items():
            for path, response_data in paths_data.items():
                if isinstance(response_data, dict) and 'error' not in response_data:
                    probe_results.append({
                        'port': port,
                        'path': path,
                        'status_code': response_data.get('status_code', 0),
                        'headers': response_data.get('headers', {}),
                        'body': response_data.get('body', '')
                    })
        
        # Match signatures
        protocol_matches = signature_matcher.match_protocol_signatures(probe_results)
        
        # Optional AI fallback
        ai_results = []
        if ai_fallback and (not protocol_matches or max(m.confidence for m in protocol_matches) < 0.7):
            try:
                ai_detector = AIServiceDetector()
                if ai_detector.openai_api_key or ai_detector.anthropic_api_key:
                    # Prepare scan data for AI
                    scan_data = {
                        'nmap': {
                            'ports': discovery_result.open_ports,
                            'services': {}
                        },
                        'probes': {f"{p['port']}{p['path']}": p for p in probe_results}
                    }
                    
                    ai_protocol, ai_confidence, ai_evidence = ai_detector.analyze_service_with_ai(ip, scan_data, 1)
                    if ai_protocol:
                        ai_results.append({
                            'protocol': ai_protocol,
                            'confidence': ai_confidence,
                            'source': 'ai_fallback',
                            'evidence': ai_evidence
                        })
            except Exception as e:
                # AI fallback failed, continue without it
                pass
        
        # Format results
        detected_protocols = []
        for match in protocol_matches:
            detected_protocols.append({
                'protocol': match.protocol,
                'confidence': match.confidence,
                'signature': match.signature_name,
                'evidence': match.evidence,
                'source': 'signature_match'
            })
        
        # Add AI results
        detected_protocols.extend(ai_results)
        
        return {
            "data": {
                "ip": ip,
                "open_ports": discovery_result.open_ports,
                "detected_protocols": detected_protocols,
                "http_responses": discovery_result.http_responses
            },
            "error": None,
            "meta": {
                "protocols_available": len(signature_matcher.protocol_signatures),
                "open_ports": len(discovery_result.open_ports),
                "scanned_ports": len(ports),
                "detected_protocols": len(detected_protocols),
                "duration_seconds": discovery_result.duration_seconds,
                "ai_fallback_used": bool(ai_results)
            },
            "result_type": "success"
        }
        
    except Exception as e:
        return {
            "data": [],
            "error": str(e),
            "meta": {"protocols_available": 0, "open_ports": 0},
            "result_type": "error"
        }


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
            print(json.dumps(result, indent=2))
            
            # Exit with error code if result_type is error
            if result.get("result_type") == "error":
                sys.exit(1)
                
        except KeyboardInterrupt:
            print(json.dumps({
                "data": [],
                "error": "Discovery cancelled by user",
                "meta": {"protocols_available": 0, "open_ports": 0},
                "result_type": "error"
            }), file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(json.dumps({
                "data": [],
                "error": str(e),
                "meta": {"protocols_available": 0, "open_ports": 0},
                "result_type": "error"
            }), file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main() 