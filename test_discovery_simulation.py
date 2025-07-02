#!/usr/bin/env python3
"""
Test discovery with actual probe configuration similar to the log output
"""

import json
from pgdn_discovery.discovery_components.probe_scanner import ProbeScanner
from pgdn_discovery.discovery_client import PGDNDiscovery


def test_sui_node_discovery():
    """Test discovery against a Sui node (simulated)"""
    print("Testing discovery against Sui node...")
    print("=" * 50)
    
    # Create test probes similar to what was shown in the log
    test_probes = [
        {'protocol': 'sui', 'port': 9000},
        {'protocol': 'sui', 'port': 9001}, 
        {'protocol': 'sui', 'port': 9184},
        {'protocol': 'sui', 'port': 9443},
        {'protocol': 'sui', 'port': 9000, 'path': '/metrics'},
        {'protocol': 'sui', 'port': 9000, 'path': '/health'},
        {'protocol': 'sui', 'port': 9000, 'path': '/status'},
        {'protocol': 'sui', 'port': 9000, 'path': '/info'},
        {'protocol': 'walrus', 'port': 8080},
        {'protocol': 'walrus', 'port': 31415}
    ]
    
    # Since we can't actually call the real server, let's simulate what would happen
    # if we got actual Sui responses
    
    # Mock a Sui health check response (this is what a real Sui node might return)
    sui_health_response = '''
    {"status": "ok", "health": "running", "network": "mainnet"}
    '''
    
    # Mock a generic response that might happen on other ports
    generic_response = '''
    {"message": "Service running"}
    '''
    
    # Create mock probe results
    mock_probe_results = [
        {
            'ip': 'sui.wizardfiction.com',
            'port': 9000,
            'path': '/health',
            'status_code': 200,
            'headers': {'content-type': 'application/json'},
            'body': sui_health_response,
            'matched_banners': [],
            'protocol_matches': [],
            'error': None,
            'tls_info': None
        },
        {
            'ip': 'sui.wizardfiction.com', 
            'port': 31415,  # Walrus port
            'path': '/',
            'status_code': 200,
            'headers': {'content-type': 'application/json'},
            'body': generic_response,  # Generic response, not Walrus-specific
            'matched_banners': [],
            'protocol_matches': [],
            'error': None,
            'tls_info': None
        }
    ]
    
    # Use the signature matcher to analyze these responses
    from pgdn_discovery.discovery_components.protocol_signatures import ProtocolSignatureMatcher
    matcher = ProtocolSignatureMatcher()
    
    # Convert to format expected by signature matcher
    signature_probe_data = []
    for result in mock_probe_results:
        signature_probe_data.append({
            'port': result['port'],
            'path': result['path'],
            'status_code': result['status_code'],
            'headers': result['headers'],
            'body': result['body']
        })
    
    matches = matcher.match_protocol_signatures(signature_probe_data)
    
    print("SIGNATURE MATCHING RESULTS:")
    print("-" * 30)
    if matches:
        for match in matches:
            print(f"Protocol: {match.protocol}")
            print(f"Confidence: {match.confidence:.1%}")
            print(f"Signature: {match.signature_name}")
            print(f"Port: {match.evidence.get('port')}")
            print(f"Path: {match.evidence.get('path')}")
            print(f"Matched: {match.matched_content[:50]}...")
            print()
    else:
        print("No protocol signatures matched")
    
    print("\nEXPECTED BEHAVIOR:")
    print("- The Sui health check should match Sui signatures")
    print("- The generic response on port 31415 should NOT match Walrus")
    print("- This should prevent false Walrus detection")


def test_with_actual_sui_metrics():
    """Test with realistic Sui metrics response"""
    print("\n" + "=" * 60)
    print("Testing with realistic Sui metrics response...")
    print("=" * 60)
    
    # Realistic Sui metrics that would be returned from /metrics endpoint
    sui_metrics = '''# HELP sui_node_build_info Build information about the Sui node
# TYPE sui_node_build_info gauge
sui_node_build_info{version="1.21.0",commit="a1b2c3d4",branch="main"} 1

# HELP sui_validator_epoch Current epoch number
# TYPE sui_validator_epoch gauge  
sui_validator_epoch{validator_address="0x1234..."} 42

# HELP sui_consensus_committed_transactions_total Total number of committed transactions
# TYPE sui_consensus_committed_transactions_total counter
sui_consensus_committed_transactions_total 1234567

# HELP sui_network_peers Number of network peers
# TYPE sui_network_peers gauge
sui_network_peers 25

# HELP sui_rpc_requests_total Total RPC requests
# TYPE sui_rpc_requests_total counter
sui_rpc_requests_total{method="sui_getObject"} 123
sui_rpc_requests_total{method="sui_getTransaction"} 456'''
    
    probe_data = [{
        'port': 9184,
        'path': '/metrics', 
        'status_code': 200,
        'headers': {'content-type': 'text/plain; version=0.0.4; charset=utf-8'},
        'body': sui_metrics
    }]
    
    from pgdn_discovery.discovery_components.protocol_signatures import ProtocolSignatureMatcher
    matcher = ProtocolSignatureMatcher()
    matches = matcher.match_protocol_signatures(probe_data)
    
    print("REALISTIC SUI METRICS RESULTS:")
    print("-" * 40)
    for match in matches:
        print(f"✅ Protocol: {match.protocol}")
        print(f"✅ Confidence: {match.confidence:.1%}")
        print(f"✅ Signature: {match.signature_name}")
        print(f"✅ Version detected: {match.evidence.get('version', 'N/A')}")
        print(f"✅ Evidence: {match.evidence.get('signature_type')}")
        if match.evidence.get('multiple_signatures'):
            print(f"✅ Multiple signatures: {match.evidence['all_signatures']}")
        print()


if __name__ == "__main__":
    test_sui_node_discovery()
    test_with_actual_sui_metrics()
    
    print("\n" + "🎯 CONCLUSION:")
    print("The new signature matching system should prevent false Walrus detection")
    print("by requiring specific Walrus signatures instead of generic responses.")
