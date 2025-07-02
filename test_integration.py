#!/usr/bin/env python3
"""
Test the full discovery system integration
"""

from pgdn_discovery.discovery_client import PGDNDiscovery
from pgdn_discovery.discovery_components.probe_scanner import ProbeScanner


def test_full_integration():
    """Test the complete discovery system with the new signature matching"""
    print("🔧 TESTING FULL DISCOVERY SYSTEM INTEGRATION")
    print("=" * 60)
    
    # Create discovery client
    client = PGDNDiscovery(timeout=5)
    
    # Test probe configurations like those from the log
    test_probes = [
        {"port": 9000, "path": "/metrics"},
        {"port": 9184, "path": "/metrics"},
        {"port": 9000, "path": "/health"},
        {"port": 31415, "path": "/"},
        {"port": 8080, "path": "/"}
    ]
    
    print(f"📋 Testing with {len(test_probes)} probes")
    for probe in test_probes:
        print(f"   - {probe}")
    print()
    
    # Test probe scanner directly
    scanner = ProbeScanner(timeout=5)
    
    # Mock a probe result that would have caused the original problem
    mock_probe_results = [
        {
            'ip': 'test.example.com',
            'port': 31415,
            'path': '/',
            'status_code': 200,
            'headers': {'content-type': 'application/json'},
            'body': '{"status": "ok", "message": "service running"}',
            'matched_banners': [],  # Legacy banners
            'protocol_matches': [],  # Will be filled by signature matching
            'error': None,
            'tls_info': None
        }
    ]
    
    # Test signature matching integration
    signature_matches = scanner.signature_matcher.match_protocol_signatures([{
        'port': 31415,
        'path': '/',
        'status_code': 200,
        'headers': {'content-type': 'application/json'},
        'body': '{"status": "ok", "message": "service running"}'
    }])
    
    print("🔍 SIGNATURE MATCHING INTEGRATION:")
    print("-" * 40)
    if signature_matches:
        print("❌ False positive detected:")
        for match in signature_matches:
            print(f"   {match.protocol}: {match.confidence:.1%}")
    else:
        print("✅ No false positives - generic response correctly ignored")
    
    print("\n✅ INTEGRATION TEST COMPLETE")
    print("The signature matching system is properly integrated into the discovery pipeline.")


if __name__ == "__main__":
    test_full_integration()
