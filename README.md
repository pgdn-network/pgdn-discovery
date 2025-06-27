# PGDN Discovery

A professional Python library for discovering DePIN (Decentralized Physical Infrastructure Network) protocols on network nodes. Designed as a library-first tool with optional command-line interface for protocol probing and detection.

## Features

- 🔍 **Professional Discovery API**: Clean, configurable discovery methods and tools
- 🚀 **High Performance**: Fast network probing with nmap integration
- 🤖 **AI-Powered Analysis**: Advanced protocol identification using OpenAI/Anthropic APIs
- 📊 **Confidence Scoring**: Reliable confidence levels for protocol detection
- 🔧 **Library First**: Clean Python package structure with modular components
- 🎯 **Evidence-Based**: Detailed evidence collection for protocol identification
- 📄 **Structured Results**: Standardized result objects with full metadata
- ⚡ **Nmap Integration**: Professional-grade port scanning capabilities

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

## Library Usage

### Basic Network Discovery

The core discovery functionality:

```python
from pgdn_discovery import discover_node, NetworkProber

# Quick discovery using the convenience function
result = discover_node("192.168.1.100")
print(f"Open ports: {result['open_ports']}")
print(f"HTTP responses: {result['http_responses']}")

# Advanced usage with NetworkProber class
prober = NetworkProber(timeout=10)
result = prober.discover("192.168.1.100", stage="all")
print(f"Duration: {result.duration_seconds}s")
```

### Targeted Protocol Probing

For specific port/path combinations using the CLI with JSON input:

```python
from pgdn_discovery.discovery_components.probe_scanner import ProbeScanner

# Initialize probe scanner
scanner = ProbeScanner(timeout=5)

# Define probes
probes = [
    {"protocol": "sui", "port": 9000, "path": "/metrics"},
    {"protocol": "ethereum", "port": 8545, "path": "/"}
]

# Run probes
result = scanner.probe_services("192.168.1.100", probes)
if not result.error:
    for probe_data in result.data:
        print(f"Port {probe_data.port}: {probe_data.status_code}")
```

### Staged Discovery

Run discovery in stages:

```python
from pgdn_discovery import NetworkProber

prober = NetworkProber(timeout=5)

# Stage 1: Port scanning only
result = prober.discover("192.168.1.100", stage="1")
print(f"Open ports: {result.open_ports}")

# Stage 2: Web scanning only (assumes ports are open)
result = prober.discover("192.168.1.100", stage="2", ports=[80, 443, 9000])
print(f"HTTP responses: {result.http_responses}")

# All stages
result = prober.discover("192.168.1.100", stage="all")
```

### Custom Ports and Paths

Specify custom ports and paths for discovery:

```python
from pgdn_discovery import discover_node, COMMON_PORTS, COMMON_ENDPOINTS

# Use custom ports and paths
custom_ports = [80, 443, 8080, 9000]
custom_paths = ["/", "/metrics", "/api/v1/status"]

result = discover_node(
    "192.168.1.100",
    ports=custom_ports,
    paths=custom_paths,
    timeout=10
)
```

### Default Constants

```python
from pgdn_discovery import COMMON_PORTS, COMMON_ENDPOINTS

print("Default ports:", COMMON_PORTS)
# Output: [80, 443, 8080, 9000, 8545, 30303]

print("Default endpoints:", COMMON_ENDPOINTS)
# Output: ["/, "/metrics", "/health", "/rpc/v0", "/status"]
```

## Discovery Result Format

The `DiscoveryResult` object provides comprehensive information:

```python
@dataclass
class DiscoveryResult:
    ip: str                          # Target IP address
    open_ports: List[int]           # List of open ports found
    http_responses: Dict[int, Dict[str, Dict[str, Any]]]  # Port -> Path -> Response data
    tls_info: Dict[int, Dict[str, Any]]  # TLS certificate info by port
    errors: Dict[str, str]          # Any errors encountered
    timestamp: str                  # ISO timestamp
    duration_seconds: float         # Discovery duration
    
    def to_dict(self) -> Dict[str, Any]:  # Convert to dictionary
        return asdict(self)
```

## CLI Usage

The package includes a command-line interface for targeted protocol probing.

### Two-Stage Discovery CLI

The CLI accepts JSON protocol definitions and performs targeted probing:

```bash
# Probe specific protocol endpoints
echo '[{"protocol":"sui","results":[{"port":9000,"path":"/metrics"}]}]' | pgdn-discovery probe 192.168.1.100

# From file
pgdn-discovery probe 192.168.1.100 --input protocols.json

# With custom timeout
pgdn-discovery probe 192.168.1.100 --input protocols.json --timeout 10
```

### Input JSON Format

```json
[
  {
    "protocol": "sui",
    "results": [
      {
        "port": 9000,
        "path": "/metrics"
      }
    ]
  },
  {
    "protocol": "ethereum",
    "results": [
      {
        "port": 8545,
        "path": "/"
      }
    ]
  }
]
```

## Package Structure

The library is organized into modular components:

```
pgdn_discovery/
├── __init__.py                   # Main package exports
├── discovery.py                  # Core NetworkProber class
├── discovery_client.py           # Enhanced discovery client
├── discovery_components/         # Discovery components
│   ├── probe_scanner.py         # Two-stage probe scanner
│   ├── ai_detector.py           # AI-powered detection
│   ├── binary_matcher.py        # Protocol matching
│   ├── config_helper.py         # Configuration utilities
│   └── nmap_scanner.py          # Network scanning
├── core/
│   └── logging.py               # Logging utilities
└── tools/
    └── __init__.py              # Tool utilities

cli.py                           # CLI entry point
tests.py                         # Test suite
setup.py                         # Package configuration
```

## Supported Protocols

Currently detects these DePIN protocols:

- **Filecoin/IPFS** - Storage networks and gateways
- **Ethereum** - Execution and consensus clients
- **Sui** - Full nodes and validators
- **Celestia** - Data availability nodes
- **Cosmos/Tendermint** - Consensus and application layers
- **Polkadot/Substrate** - Relay and parachain nodes
- **Solana** - Validators and RPC nodes
- **Theta** - Video delivery networks
- **Helium** - IoT and mobile networks

Detection uses multiple methods:
1. **Port Scanning** - Protocol-specific ports with nmap
2. **HTTP Endpoints** - API endpoint probing
3. **Banner Analysis** - Service banner pattern matching
4. **Content Analysis** - Response content signatures
5. **AI Analysis** - Machine learning protocol identification

## Advanced Usage

### Batch Discovery

```python
from concurrent.futures import ThreadPoolExecutor
from pgdn_discovery import discover_node

def discover_network_range(network_base="192.168.1", start=1, end=254):
    """Discover all nodes in a network range"""
    
    def discover_single(ip):
        host = f"{network_base}.{ip}"
        return discover_node(host, timeout=5)
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        hosts = range(start, end + 1)
        results = list(executor.map(discover_single, hosts))
    
    # Filter successful discoveries
    found_nodes = [r for r in results if r['open_ports']]
    return found_nodes

# Usage
nodes = discover_network_range("192.168.1", 1, 50)
for node in nodes:
    print(f"Found open ports {node['open_ports']} at {node['ip']}")
```

### Custom Protocol Detection

```python
# Use the CLI with custom protocol definitions
import json
import subprocess

custom_protocols = [
    {
        "protocol": "custom_service",
        "results": [
            {"port": 1234, "path": "/custom/api"},
            {"port": 5678, "path": "/health"}
        ]
    }
]

# Write to file and use CLI
with open('custom_protocols.json', 'w') as f:
    json.dump(custom_protocols, f)

result = subprocess.run([
    'pgdn-discovery', 'probe', '192.168.1.100',
    '--input', 'custom_protocols.json'
], capture_output=True, text=True)

print(result.stdout)
```

## Development

### Core Components

- **NetworkProber**: Main discovery class with staged scanning
- **ProbeScanner**: Targeted protocol probing with nmap integration
- **DiscoveryResult**: Standardized result format
- **discover_node**: Convenience function for quick discovery

### Adding New Protocols

The modular design allows easy protocol addition:

1. **Add signature patterns** in the appropriate discovery component
2. **Update probe configurations** for new protocol ports/endpoints
3. **Train AI models** with new protocol examples (optional)

### Running Tests

```bash
python tests.py
```

## Examples

### Basic Port Scanning

```python
from pgdn_discovery import NetworkProber

prober = NetworkProber(timeout=5)
result = prober.discover("192.168.1.100", stage="1")
print(f"Found {len(result.open_ports)} open ports: {result.open_ports}")
```

### HTTP Service Discovery

```python
from pgdn_discovery import discover_node

result = discover_node("192.168.1.100", stage="2", ports=[80, 443, 8080])
for port, responses in result['http_responses'].items():
    for path, data in responses.items():
        if 'status_code' in data:
            print(f"Port {port}{path}: HTTP {data['status_code']}")
```

## Performance Considerations

- **Concurrent Discovery**: Use ThreadPoolExecutor for multiple targets
- **Timeout Management**: Set appropriate timeouts based on network conditions
- **Method Selection**: Choose specific methods instead of running all
- **Caching**: Consider caching results for frequently scanned targets
- **Rate Limiting**: Implement delays for large-scale scanning to avoid overwhelming targets

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## Support

- 📧 Email: team@pgdn.network
- 🐛 Issues: [GitHub Issues](https://github.com/pgdn-network/pgdn-discovery/issues)
- 📖 Documentation: [GitHub Wiki](https://github.com/pgdn-network/pgdn-discovery/wiki)
