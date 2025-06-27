# PGDN Discovery

A lightweight library for discovering DePIN (Decentralized Physical Infrastructure Network) protocols on network nodes. Works both as a command-line tool and as a Python library.

## Features

- 🔍 **Protocol Detection**: Automatically identify common DePIN protocols (Filecoin, Ethereum, Sui, etc.)
- 🚀 **High Performance**: Fast network scanning with intelligent port detection
- 📊 **Confidence Scoring**: Get confidence levels for protocol detection
- 🔧 **Dual Interface**: Use as CLI tool or Python library
- 📈 **Performance Metrics**: Track scanning time and coverage
- 🎯 **Evidence-Based**: Detailed evidence collection for protocol identification

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

## CLI Usage

### Basic Usage

```bash
# Discover protocol on a host
pgdn-discovery 192.168.1.100

# Get JSON output
pgdn-discovery example.com --json

# With custom timeout and node ID
pgdn-discovery 10.0.0.1 --node-id abc123 --timeout 60

# Enable debug logging
pgdn-discovery 192.168.1.100 --debug
```

### CLI Options

```
pgdn-discovery --help

usage: pgdn-discovery [-h] [--node-id NODE_ID] [--timeout TIMEOUT] [--json] [--debug] host

PGDN Discovery - Simple DePIN Protocol Discovery Tool

positional arguments:
  host                 Target host IP address or hostname

options:
  -h, --help           show this help message and exit
  --node-id NODE_ID    Optional node identifier
  --timeout TIMEOUT    Network timeout in seconds (default: 30)
  --json               Output results in JSON format
  --debug              Enable debug logging
```

### Example CLI Output

```bash
$ pgdn-discovery 192.168.1.100

🔍 Discovery Results for 192.168.1.100
==================================================
✅ Protocol Detected: FILECOIN
🎯 Confidence: HIGH (0.85)

📊 Evidence Summary:
   Port Matches: 2 matches
   Content Matches: 3 matches
   Header Matches: 1 matches

⚡ Performance:
   Discovery time: 2.3 seconds
   Ports scanned: 12
   HTTP endpoints: 8
```

## Library Usage

### Simple Discovery

```python
from pgdn_discovery import discover_node

# Basic usage
result = discover_node("192.168.1.100")

if result["success"]:
    protocol = result["result"]["protocol"]
    confidence = result["result"]["confidence"]
    score = result["result"]["confidence_score"]
    
    print(f"Detected: {protocol} (confidence: {confidence}, score: {score})")
else:
    print(f"Discovery failed: {result['error']}")
```

### Advanced Usage with Client

```python
from pgdn_discovery import create_discovery_client

# Create a reusable client
client = create_discovery_client(timeout=60, debug=True)

# Discover multiple hosts
hosts = ["192.168.1.100", "192.168.1.101", "example.com"]

for host in hosts:
    result = client.discover_node(host)
    if result["success"]:
        protocol = result["result"]["protocol"]
        print(f"{host}: {protocol}")
```

### Response Format

The library returns results in the following format:

```python
{
    "success": True,
    "operation": "discovery",
    "host": "192.168.1.100",
    "node_id": "optional-node-id",
    "result": {
        "protocol": "filecoin",           # Detected protocol or None
        "confidence": "high",             # high, medium, low, unknown
        "confidence_score": 0.85,         # 0.0 to 1.0
        "evidence": {
            "port_matches": {...},        # Evidence from port scanning
            "content_matches": {...},     # Evidence from HTTP content
            "header_matches": {...},      # Evidence from HTTP headers
            "banner_matches": {...}       # Evidence from TCP banners
        },
        "scan_data": {
            "open_ports": [22, 80, 1234],
            "http_responses": {...},
            "tcp_banners": {...}
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

More protocols will be added based on community needs.

## Development

### Running from Source

```bash
# Run as module
python -m pgdn_discovery 192.168.1.100

# Run directly
python pgdn_discovery.py 192.168.1.100
```

### Testing

```bash
# Test CLI
pgdn-discovery --help

# Test library import
python -c "from pgdn_discovery import discover_node; print('Import successful')"
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- 📧 Email: team@pgdn.network
- 🐛 Issues: [GitHub Issues](https://github.com/pgdn-network/pgdn-discovery/issues)
- 📖 Documentation: [GitHub Wiki](https://github.com/pgdn-network/pgdn-discovery/wiki)
