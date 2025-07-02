#!/usr/bin/env python3
"""
Test the exact scenario from the user's log to verify the fix
"""

import json
from pgdn_discovery.discovery_components.protocol_signatures import ProtocolSignatureMatcher


def test_original_problem_scenario():
    """
    Test the exact scenario from the original log where:
    - A Sui node is running on sui.wizardfiction.com
    - Probes include both Sui and Walrus ports
    - Port 31415 (Walrus port) returns a generic response
    - Should NOT be misidentified as Walrus
    """
    print("🧪 TESTING ORIGINAL PROBLEM SCENARIO")
    print("=" * 60)
    
    # Simulate the probes from the log
    test_probes = [
        {'protocol': 'sui', 'port': 9000, 'path': '/'},
        {'protocol': 'sui', 'port': 9001, 'path': '/'},
        {'protocol': 'sui', 'port': 9184, 'path': '/'},
        {'protocol': 'sui', 'port': 9443, 'path': '/'},
        {'protocol': 'sui', 'port': 9000, 'path': '/metrics'},
        {'protocol': 'sui', 'port': 9000, 'path': '/health'},
        {'protocol': 'sui', 'port': 9000, 'path': '/status'},
        {'protocol': 'sui', 'port': 9000, 'path': '/info'},
        {'protocol': 'walrus', 'port': 8080, 'path': '/'},
        {'protocol': 'walrus', 'port': 31415, 'path': '/'}
    ]
    
    print(f"📊 Testing with {len(test_probes)} probes:")
    sui_probes = [p for p in test_probes if p['protocol'] == 'sui']
    walrus_probes = [p for p in test_probes if p['protocol'] == 'walrus']
    print(f"   - Sui probes: {len(sui_probes)}")
    print(f"   - Walrus probes: {len(walrus_probes)}")
    print()
    
    # Simulate realistic responses for a Sui node
    mock_responses = []
    
    # 1. Sui metrics endpoint - should strongly match Sui
    mock_responses.append({
        'port': 9184,
        'path': '/metrics',
        'status_code': 200,
        'headers': {'content-type': 'text/plain; version=0.0.4; charset=utf-8'},
        'body': '''# HELP sui_node_build_info Build information about the Sui node
# TYPE sui_node_build_info gauge
sui_node_build_info{version="1.21.0",commit="abc123def",branch="main"} 1

# HELP sui_validator_epoch Current epoch number  
# TYPE sui_validator_epoch gauge
sui_validator_epoch{validator_address="0x1234..."} 156

# HELP sui_consensus_committed_transactions_total Total committed transactions
# TYPE sui_consensus_committed_transactions_total counter
sui_consensus_committed_transactions_total 987654

# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 123.45'''
    })
    
    # 2. Sui health check - should match Sui
    mock_responses.append({
        'port': 9000,
        'path': '/health',
        'status_code': 200,
        'headers': {'content-type': 'application/json'},
        'body': '''{"status": "ok", "network": "mainnet", "sui": {"version": "1.21.0"}}'''
    })
    
    # 3. Port 31415 (Walrus port) with generic response - should NOT match Walrus
    mock_responses.append({
        'port': 31415,
        'path': '/',
        'status_code': 200,
        'headers': {'content-type': 'application/json'},
        'body': '''{"message": "Service is running", "status": "ok", "version": "1.0.0"}'''
    })
    
    # 4. Port 8080 with generic web server response - should NOT match Walrus  
    mock_responses.append({
        'port': 8080,
        'path': '/',
        'status_code': 200,
        'headers': {'content-type': 'text/html'},
        'body': '''<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>Server Running</h1></body></html>'''
    })
    
    # Test signature matching
    matcher = ProtocolSignatureMatcher()
    matches = matcher.match_protocol_signatures(mock_responses)
    
    print("🔍 SIGNATURE MATCHING RESULTS:")
    print("-" * 40)
    
    if matches:
        for i, match in enumerate(matches, 1):
            print(f"{i}. Protocol: {match.protocol}")
            print(f"   Confidence: {match.confidence:.1%}")
            print(f"   Signature: {match.signature_name}")
            print(f"   Port: {match.evidence.get('port')}")
            print(f"   Path: {match.evidence.get('path')}")
            print(f"   Type: {match.evidence.get('signature_type')}")
            if match.evidence.get('version'):
                print(f"   Version: {match.evidence.get('version')}")
            print()
    else:
        print("❌ No matches found")
    
    # Analyze results
    print("📋 ANALYSIS:")
    print("-" * 20)
    
    sui_matches = [m for m in matches if m.protocol == 'sui']
    walrus_matches = [m for m in matches if m.protocol == 'walrus']
    
    print(f"✅ Sui matches: {len(sui_matches)}")
    if sui_matches:
        best_sui = max(sui_matches, key=lambda x: x.confidence)
        print(f"   Best: {best_sui.signature_name} ({best_sui.confidence:.1%} confidence)")
    
    print(f"❌ Walrus matches: {len(walrus_matches)}")
    if walrus_matches:
        best_walrus = max(walrus_matches, key=lambda x: x.confidence)  
        print(f"   Best: {best_walrus.signature_name} ({best_walrus.confidence:.1%} confidence)")
    
    print("\n🎯 EXPECTED BEHAVIOR:")
    print("✅ Should detect Sui with high confidence from /metrics and /health")
    print("❌ Should NOT detect Walrus from generic responses on ports 31415/8080")
    print("✅ This prevents the false positive Walrus detection from the original issue")
    
    # Final verdict
    print("\n" + "="*60)
    if sui_matches and not walrus_matches:
        print("🎉 SUCCESS: Problem solved!")
        print("   - Sui correctly detected")
        print("   - Walrus false positive prevented")
    elif sui_matches and walrus_matches:
        print("⚠️  PARTIAL: Sui detected but Walrus false positive still occurs")
    elif walrus_matches and not sui_matches:
        print("❌ FAILURE: Still getting false Walrus detection")
    else:
        print("❓ UNCLEAR: No protocols detected")


def test_walrus_true_positive():
    """Test that we can still detect actual Walrus nodes"""
    print("\n\n🧪 TESTING WALRUS TRUE POSITIVE DETECTION")
    print("=" * 60)
    
    # Simulate actual Walrus node response
    walrus_response = {
        'port': 31415,
        'path': '/api/v1/status',
        'status_code': 200,
        'headers': {
            'content-type': 'application/json',
            'x-walrus-version': '0.2.1',
            'x-walrus-node-id': 'wal-node-abc123'
        },
        'body': '''{"walrus": {"version": "0.2.1", "network": "testnet"}, "storage": {"api": "/api/v1/storage", "available": true}, "status": "healthy"}'''
    }
    
    matcher = ProtocolSignatureMatcher()
    matches = matcher.match_protocol_signatures([walrus_response])
    
    print("🔍 WALRUS DETECTION RESULTS:")
    print("-" * 40)
    
    if matches:
        for match in matches:
            print(f"Protocol: {match.protocol}")
            print(f"Confidence: {match.confidence:.1%}")
            print(f"Signature: {match.signature_name}")
            print(f"Evidence: {match.evidence.get('signature_type')}")
    else:
        print("❌ No Walrus detected")
    
    walrus_detected = any(m.protocol == 'walrus' for m in matches)
    print(f"\n🎯 Result: {'✅ Walrus correctly detected' if walrus_detected else '❌ Failed to detect actual Walrus'}")


if __name__ == "__main__":
    test_original_problem_scenario()
    test_walrus_true_positive()
    
    print("\n" + "🏁 CONCLUSION:")
    print("The new signature-based matching system should solve the original problem")
    print("by requiring specific protocol signatures instead of generic responses.")
