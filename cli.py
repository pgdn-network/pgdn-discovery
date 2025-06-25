"""
PGDN Discover CLI - Simple DePIN Protocol Discovery Tool

A lightweight command-line tool for discovering DePIN protocols on network nodes.
"""

import argparse
import json
import sys
from typing import Dict, Any

from lib.discovery import discover_node


def print_json_result(result: Dict[str, Any]) -> None:
    """Print result as JSON"""
    print(json.dumps(result, indent=2))


def print_human_result(result: Dict[str, Any]) -> None:
    """Print result in human-readable format"""
    if not result.get('success', False):
        print(f"❌ Discovery failed: {result.get('error', 'Unknown error')}")
        return
    
    host = result.get('host', 'unknown')
    discovery_result = result.get('result', {})
    
    print(f"🔍 Discovery Results for {host}")
    print("=" * 50)
    
    protocol = discovery_result.get('protocol')
    confidence = discovery_result.get('confidence', 'unknown')
    confidence_score = discovery_result.get('confidence_score', 0.0)
    
    if protocol:
        print(f"✅ Protocol Detected: {protocol.upper()}")
        print(f"🎯 Confidence: {confidence.upper()} ({confidence_score:.2f})")
    else:
        print("❓ No protocol detected")
        print(f"🎯 Confidence: {confidence.upper()}")
    
    # Show evidence summary
    evidence = discovery_result.get('evidence', {})
    print(f"\n📊 Evidence Summary:")
    
    for evidence_type, matches in evidence.items():
        if matches:
            count = sum(len(v) if isinstance(v, list) else 1 for v in matches.values())
            print(f"   {evidence_type.replace('_', ' ').title()}: {count} matches")
    
    # Show performance metrics
    metrics = discovery_result.get('performance_metrics', {})
    if metrics:
        print(f"\n⚡ Performance:")
        print(f"   Discovery time: {metrics.get('discovery_time_seconds', 0)} seconds")
        print(f"   Ports scanned: {metrics.get('scanned_ports', 0)}")
        print(f"   HTTP endpoints: {metrics.get('http_endpoints_checked', 0)}")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="PGDN Discover - Simple DePIN Protocol Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pgdn-discover 192.168.1.100                    # Discover protocol on host
  pgdn-discover example.com --json               # JSON output
  pgdn-discover 10.0.0.1 --node-id abc123       # With node ID
  pgdn-discover 192.168.1.100 --timeout 60      # Custom timeout
        """
    )
    
    parser.add_argument(
        'host',
        help='Target host IP address or hostname'
    )
    
    parser.add_argument(
        '--node-id',
        help='Optional node identifier'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Network timeout in seconds (default: 30)'
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results in JSON format'
    )
    
    args = parser.parse_args()
    
    try:
        # Run discovery
        result = discover_node(
            host=args.host,
            node_id=args.node_id,
            timeout=args.timeout
        )
        
        # Wrap the discovery result in the expected format
        wrapped_result = {
            "success": True,
            "host": args.host,
            "result": result
        }
        
        # Print results
        if args.json:
            print_json_result(wrapped_result)
        else:
            print_human_result(wrapped_result)
        
        # Exit with error code if discovery failed
        if not wrapped_result.get('success', False):
            sys.exit(1)
            
    except KeyboardInterrupt:
        error_msg = "Discovery cancelled by user"
        if args.json:
            print(json.dumps({"success": False, "error": error_msg}))
        else:
            print(f"\n⚠️  {error_msg}")
        sys.exit(1)
        
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        if args.json:
            print(json.dumps({"success": False, "error": error_msg}))
        else:
            print(f"❌ {error_msg}")
        sys.exit(1)


if __name__ == "__main__":
    main()
