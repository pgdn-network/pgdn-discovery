# PGDN Discover

A lightweight Python library for discovering DePIN (Decentralized Physical Infrastructure Network) protocols on network nodes.

## Features

- **Simple**: No complex agent architecture or database dependencies
- **Fast**: Efficient network scanning and protocol detection
- **JSON Output**: All results returned as JSON objects
- **Protocol Detection**: Supports Sui, Filecoin, Ethereum, and custom protocols
- **CLI Tool**: Easy-to-use command-line interface

## Installation

```bash
pip install -r requirements_simple.txt
```

## Quick Start

### As a Library

```python
from lib.discovery import discover_node

# Discover protocol on a host
result = discover_node("192.168.1.100")

if result['success']:
    protocol = result['result']['protocol']
    confidence = result['result']['confidence']
    print(f"Detected {protocol} with {confidence} confidence")
else:
    print(f"Discovery failed: {result['error']}")
```

### CLI Usage

```bash
# Basic discovery
python cli_simple.py 192.168.1.100

# JSON output
python cli_simple.py 192.168.1.100 --json

# With node ID and custom timeout
python cli_simple.py example.com --node-id abc123 --timeout 60
```

## Output Format

Discovery results are returned as JSON objects:

```json
{
  "success": true,
  "operation": "discovery",
  "host": "192.168.1.100",
  "node_id": null,
  "result": {
    "protocol": "sui",
    "confidence": "high",
    "confidence_score": 0.85,
    "evidence": {
      "port_matches": {
        "sui": [9000, 8080]
      },
      "content_matches": {
        "sui": [
          {
            "port": 9000,
            "endpoint": "/metrics",
            "pattern": "consensus_epoch"
          }
        ]
      }
    },
    "scan_data": {
      "open_ports": [22, 8080, 9000],
      "http_responses": {...},
      "tcp_banners": {...}
    },
    "performance_metrics": {
      "discovery_time_seconds": 2.45,
      "scanned_ports": 3,
      "http_endpoints_checked": 8
    },
    "host": "192.168.1.100",
    "timestamp": "2025-06-25T10:30:00Z"
  }
}
```

## Supported Protocols

- **Sui**: Detects Sui blockchain nodes
- **Filecoin**: Detects Filecoin/Lotus nodes  
- **Ethereum**: Detects Ethereum nodes

## Protocol Detection

The library uses multiple detection methods:

1. **Port Scanning**: Checks for protocol-specific ports
2. **HTTP Endpoints**: Tests common API endpoints
3. **Content Analysis**: Searches for protocol-specific patterns
4. **Header Analysis**: Examines HTTP headers
5. **Banner Grabbing**: Analyzes TCP service banners

## Configuration

The discovery engine can be configured:

```python
from lib.discovery import ProtocolDiscovery

# Custom timeout
discovery = ProtocolDiscovery(timeout=60)
result = discovery.discover_node("192.168.1.100")
```

## Development

### Project Structure

```
lib/
├── discovery.py      # Main discovery logic
├── __init__.py       # Package initialization

cli_simple.py         # Command-line interface
setup_simple.py       # Package setup
requirements_simple.txt # Dependencies
```

### Adding New Protocols

To add support for a new protocol, update the `protocol_signatures` in `lib/discovery.py`:

```python
'my_protocol': {
    'ports': [1234, 5678],
    'endpoints': ['/api/status'],
    'content_patterns': ['my_protocol', 'version'],
    'headers': ['my-protocol-version']
}
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

For issues and questions, please open an issue on GitHub.
