# PGDN Discovery

A lightweight Python library for discovering DePIN (Decentralized Physical Infrastructure Network) protocols on network nodes. Designed for integration into other applications with both simple and advanced APIs.

## Features

- 🔍 **Protocol Detection**: Automatically identify common DePIN protocols (Filecoin, Ethereum, Sui, etc.)
- 🚀 **High Performance**: Fast network scanning with intelligent port detection
- 📊 **Confidence Scoring**: Get confidence levels for protocol detection
- 🔧 **Library First**: Designed primarily as a Python library with optional CLI
- 📈 **Performance Metrics**: Track scanning time and coverage
- 🎯 **Evidence-Based**: Detailed evidence collection for protocol identification
- 📄 **JSON Output**: All results returned as structured JSON objects
- ⚡ **No Dependencies**: Minimal external dependencies for easy integration

## Installation

```bash
pip install pgdn-discovery
```

Or install from source:

```bash
git clone https://github.com/pgdn-network/pgdn-discovery.git
cd pgdn-discovery
pip install -e .
```

For development:

```bash
pip install -r requirements.txt
```

## Library Usage

### Quick Start

The simplest way to use PGDN Discovery in your application:

```python
from pgdn_discovery import discover_node

# Basic discovery
result = discover_node("192.168.1.100")

if result["success"]:
    protocol = result["result"]["protocol"]
    confidence = result["result"]["confidence"]
    score = result["result"]["confidence_score"]
    print(f"Detected: {protocol} (confidence: {confidence}, score: {score})")
else:
    print(f"Discovery failed: {result['error']}")
```

### Advanced Library Integration

For applications that need to discover multiple nodes or require custom configuration:

```python
from pgdn_discovery import create_discovery_client

# Create a reusable client with custom settings
client = create_discovery_client(
    timeout=60,
    debug=True,
    custom_ports=[8080, 9000, 3000]  # Add custom ports to scan
)

# Discover multiple hosts efficiently
hosts = ["192.168.1.100", "192.168.1.101", "example.com"]
results = []

for host in hosts:
    result = client.discover_node(host, node_id=f"node-{host}")
    results.append(result)
    
    if result["success"]:
        protocol = result["result"]["protocol"]
        print(f"{host}: {protocol}")
    else:
        print(f"{host}: Failed - {result['error']}")

# Access detailed evidence for each discovery
for result in results:
    if result["success"]:
        evidence = result["result"]["evidence"]
        ports = result["result"]["scan_data"]["open_ports"]
        print(f"Open ports on {result['host']}: {ports}")
```

### Integration with Web Applications

Example Flask integration:

```python
from flask import Flask, request, jsonify
from pgdn_discovery import discover_node

app = Flask(__name__)

@app.route('/discover', methods=['POST'])
def api_discover():
    data = request.get_json()
    
    if not data or 'host' not in data:
        return jsonify({"error": "Host parameter required"}), 400
    
    host = data['host']
    node_id = data.get('node_id')
    timeout = data.get('timeout', 30)
    
    # Perform discovery
    result = discover_node(host, node_id=node_id, timeout=timeout)
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
```

### Batch Discovery for Network Analysis

For network analysis applications:

```python
import asyncio
from concurrent.futures import ThreadPoolExecutor
from pgdn_discovery import discover_node

def discover_network_range(network_base="192.168.1", start=1, end=254):
    """Discover all nodes in a network range"""
    
    def discover_single(ip):
        host = f"{network_base}.{ip}"
        return discover_node(host, timeout=10)
    
    # Use thread pool for concurrent discovery
    with ThreadPoolExecutor(max_workers=20) as executor:
        hosts = range(start, end + 1)
        results = list(executor.map(discover_single, hosts))
    
    # Filter successful discoveries
    found_nodes = []
    for result in results:
        if result["success"] and result["result"]["protocol"]:
            found_nodes.append({
                "host": result["host"],
                "protocol": result["result"]["protocol"],
                "confidence": result["result"]["confidence"],
                "confidence_score": result["result"]["confidence_score"]
            })
    
    return found_nodes

# Usage
nodes = discover_network_range("192.168.1", 1, 50)
for node in nodes:
    print(f"Found {node['protocol']} node at {node['host']}")
```

### Custom Protocol Detection

To add support for your own protocols:

```python
from pgdn_discovery import ProtocolDiscovery

# Create discovery instance with custom protocol signatures
custom_protocols = {
    'my_custom_protocol': {
        'ports': [1234, 5678],
        'endpoints': ['/api/status', '/health'],
        'content_patterns': ['my_protocol_v', 'node_version'],
        'headers': ['x-my-protocol-version']
    }
}

discovery = ProtocolDiscovery(
    timeout=30,
    custom_protocols=custom_protocols
)

result = discovery.discover_node("192.168.1.100")
```

## Response Format

All discovery results are returned as structured JSON objects:

```python
{
    "success": True,
    "operation": "discovery",
    "host": "192.168.1.100",
    "node_id": "optional-node-id",
    "result": {
        "protocol": "filecoin",           # Detected protocol name or None
        "confidence": "high",             # high, medium, low, unknown
        "confidence_score": 0.85,         # Numeric score 0.0 to 1.0
        "evidence": {
            "port_matches": {             # Ports that matched protocol signatures
                "filecoin": [1234, 5678]
            },
            "content_matches": {          # HTTP content that matched
                "filecoin": [
                    {
                        "port": 1234,
                        "endpoint": "/api/v0/id",
                        "pattern": "lotus"
                    }
                ]
            },
            "header_matches": {...},      # HTTP headers that matched
            "banner_matches": {...}       # TCP banners that matched
        },
        "scan_data": {
            "open_ports": [22, 1234, 5678],
            "http_responses": {           # Raw HTTP responses
                "1234": {
                    "/api/v0/id": {"status": 200, "content": "..."}
                }
            },
            "tcp_banners": {}             # Raw TCP banner data
        },
        "performance_metrics": {
            "discovery_time_seconds": 2.3,
            "scanned_ports": 12,
            "http_endpoints_checked": 8
        },
        "host": "192.168.1.100",
        "timestamp": "2024-01-01T12:00:00.000000"
    }
}
```

## Supported Protocols

Currently detects the following DePIN protocols:

- **Filecoin**: Lotus nodes, miners, and gateways
- **Ethereum**: Geth, consensus clients, and RPC endpoints  
- **Sui**: Full nodes and validators

The library uses multiple detection methods:

1. **Port Scanning**: Checks for protocol-specific ports
2. **HTTP Endpoints**: Tests common API endpoints
3. **Content Analysis**: Searches for protocol-specific patterns in responses
4. **Header Analysis**: Examines HTTP headers for protocol indicators
5. **Banner Grabbing**: Analyzes TCP service banners

## CLI Usage (Optional)

While designed as a library, a CLI tool is also provided:

```bash
# Basic discovery
pgdn-discovery 192.168.1.100

# JSON output for scripting
pgdn-discovery example.com --json

# With custom options
pgdn-discovery 10.0.0.1 --node-id abc123 --timeout 60 --debug
```

## Configuration Options

The library supports various configuration options:

```python
from pgdn_discovery import ProtocolDiscovery

# Create with custom configuration
discovery = ProtocolDiscovery(
    timeout=60,                    # Network timeout in seconds
    max_threads=10,                # Max concurrent threads
    port_scan_timeout=5,           # Port scan timeout
    http_timeout=10,               # HTTP request timeout
    debug=True,                    # Enable debug logging
    custom_ports=[8080, 9000],     # Additional ports to scan
    skip_ping=False                # Whether to skip initial ping test
)

result = discovery.discover_node("192.168.1.100")
```

## Error Handling

The library provides comprehensive error handling:

```python
result = discover_node("unreachable-host.example")

if not result["success"]:
    error_type = result.get("error_type", "unknown")
    error_message = result["error"]
    
    if error_type == "network_timeout":
        print("Host unreachable or too slow")
    elif error_type == "connection_refused":
        print("Connection refused by host")
    elif error_type == "dns_resolution":
        print("Could not resolve hostname")
    else:
        print(f"Discovery failed: {error_message}")
```

## Development

### Project Structure

```
lib/
├── discovery.py              # Main discovery logic
├── discovery_components/     # Core detection components
│   ├── nmap_scanner.py      # Network scanning
│   ├── binary_matcher.py    # Protocol matching
│   ├── ai_detector.py       # AI-based detection
│   └── config_helper.py     # Configuration handling
└── core/
    └── logging.py           # Logging utilities

pgdn_discovery.py            # Main entry point
setup.py                     # Package setup
requirements.txt             # Dependencies
```

### Running Tests

```bash
python tests.py
```

### Adding New Protocols

To add support for a new protocol, update the protocol signatures:

```python
# In your application or custom discovery instance
new_protocol_signature = {
    'ports': [1234, 5678],              # Known ports for this protocol
    'endpoints': ['/api/status'],        # HTTP endpoints to check
    'content_patterns': ['protocol_name', 'version'], # Text patterns to match
    'headers': ['x-protocol-version']    # HTTP headers to look for
}
```

## Performance Considerations

- **Concurrent Scanning**: Use ThreadPoolExecutor for scanning multiple hosts
- **Timeout Management**: Set appropriate timeouts based on your network
- **Port Selection**: Limit port scanning to known protocol ports for speed
- **Caching**: Consider caching results for frequently scanned hosts

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

- 📧 Email: team@pgdn.network
- 🐛 Issues: [GitHub Issues](https://github.com/pgdn-network/pgdn-discovery/issues)
- 📖 Documentation: [GitHub Wiki](https://github.com/pgdn-network/pgdn-discovery/wiki)
