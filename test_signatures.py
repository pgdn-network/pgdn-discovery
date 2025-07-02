#!/usr/bin/env python3
"""
Test the new protocol signature matching system
"""

import json
from pgdn_discovery.discovery_components.protocol_signatures import ProtocolSignatureMatcher


def test_sui_signatures():
    """Test Sui protocol signature detection"""
    matcher = ProtocolSignatureMatcher()
    
    # Mock Sui metrics response
    sui_metrics_response = '''
    # HELP sui_node_build_info Build information about the Sui node
    # TYPE sui_node_build_info gauge
    sui_node_build_info{version="1.21.0",commit="abc123"} 1
    
    # HELP sui_validator_epoch Current epoch number
    # TYPE sui_validator_epoch gauge
    sui_validator_epoch 123
    
    # HELP sui_consensus_committed_transactions Total committed transactions
    # TYPE sui_consensus_committed_transactions counter
    sui_consensus_committed_transactions 456789
    '''
    
    # Mock Sui RPC response
    sui_rpc_response = '''
    {"jsonrpc":"2.0","result":"1.21.0","id":1,"sui_getRpcApiVersion":true}
    '''
    
    # Test with Sui metrics on port 9184
    probe_results = [
        {
            'port': 9184,
            'path': '/metrics',
            'status_code': 200,
            'headers': {'content-type': 'text/plain'},
            'body': sui_metrics_response
        }
    ]
    
    matches = matcher.match_protocol_signatures(probe_results)
    print("=== SUI METRICS TEST ===")
    for match in matches:
        print(f"Protocol: {match.protocol}")
        print(f"Confidence: {match.confidence}")
        print(f"Signature: {match.signature_name}")
        print(f"Evidence: {json.dumps(match.evidence, indent=2)}")
        print()
    
    # Test with Sui RPC on port 9000
    probe_results_rpc = [
        {
            'port': 9000,
            'path': '/',
            'status_code': 200,
            'headers': {'content-type': 'application/json'},
            'body': sui_rpc_response
        }
    ]
    
    matches_rpc = matcher.match_protocol_signatures(probe_results_rpc)
    print("=== SUI RPC TEST ===")
    for match in matches_rpc:
        print(f"Protocol: {match.protocol}")
        print(f"Confidence: {match.confidence}")
        print(f"Signature: {match.signature_name}")
        print(f"Evidence: {json.dumps(match.evidence, indent=2)}")
        print()


def test_walrus_vs_sui():
    """Test that Walrus and Sui can be differentiated"""
    matcher = ProtocolSignatureMatcher()
    
    # Mock response that might look like Walrus but is actually generic
    ambiguous_response = '''
    {"status": "ok", "version": "1.0.0", "service": "generic"}
    '''
    
    # Test on Walrus port (31415) with ambiguous response
    probe_results = [
        {
            'port': 31415,
            'path': '/',
            'status_code': 200,
            'headers': {'content-type': 'application/json'},
            'body': ambiguous_response
        }
    ]
    
    matches = matcher.match_protocol_signatures(probe_results)
    print("=== AMBIGUOUS RESPONSE ON WALRUS PORT ===")
    if matches:
        for match in matches:
            print(f"Protocol: {match.protocol}")
            print(f"Confidence: {match.confidence}")
            print(f"Signature: {match.signature_name}")
    else:
        print("No matches found - good! Ambiguous response not matched")
    print()
    
    # Test with actual Walrus-like response
    walrus_response = '''
    {"walrus": {"version": "0.1.0", "storage": {"api": "/api/v1/storage"}}}
    '''
    
    probe_results_walrus = [
        {
            'port': 31415,
            'path': '/',
            'status_code': 200,
            'headers': {'content-type': 'application/json'},
            'body': walrus_response
        }
    ]
    
    matches_walrus = matcher.match_protocol_signatures(probe_results_walrus)
    print("=== ACTUAL WALRUS RESPONSE ===")
    for match in matches_walrus:
        print(f"Protocol: {match.protocol}")
        print(f"Confidence: {match.confidence}")
        print(f"Signature: {match.signature_name}")
        print()


if __name__ == "__main__":
    print("Testing Protocol Signature Matching System")
    print("=" * 50)
    
    test_sui_signatures()
    test_walrus_vs_sui()
    
    print("Testing complete!")
