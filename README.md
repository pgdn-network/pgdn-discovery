# PGDN Discovery

A professional Python library for discovering DePIN (Decentralized Physical Infrastructure Network) protocols on network nodes. Designed for both library integration and command-line usage with a clean, configurable API.

## Features

- 🔍 **Professional Discovery API**: Clean, configurable discovery methods and tools
- 🚀 **High Performance**: Fast network probing with nmap integration
- 🤖 **AI-Powered Analysis**: Advanced protocol identification using OpenAI/Anthropic APIs
- 📊 **Confidence Scoring**: Reliable confidence levels for protocol detection
- 🔧 **Library First**: Designed primarily as a Python library with optional CLI
- 📈 **Organization Tracking**: Built-in support for org_id and discovery tracking
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

### Professional Discovery API (Recommended)

The modern, clean API for professional usage:

```python
from pgdn_discovery import create_discovery_client

# Create a discovery client
client = create_discovery_client(timeout=60, debug=True)

# Run comprehensive discovery
result = client.run_discovery(
    target='192.168.1.100',
    org_id='myorg',
    enabled_methods=['probe', 'protocol', 'ai'],
    enabled_tools=['nmap', 'http_client']
)

# Check results
if result.success:
    print(f"Discovered protocol: {result.protocol}")
    print(f"Confidence: {result.confidence}")
    print(f"Discovery ID: {result.discovery_id}")
    print(f"Duration: {result.duration_seconds}s")
else:
    print(f"Discovery failed: {result.errors}")
```

### Targeted Probe Discovery

For specific port/path combinations:

```python
# Targeted probe discovery (Stage 1 + optional AI)
result = client.run_probe_discovery(
    target='192.168.1.100',
    probes=[
        {"port": 9000, "path": "/metrics"},
        {"port": 1234, "path": "/rpc/v0"}
    ],
    org_id='myorg',
    include_ai=True  # Enable AI analysis
)

print(f"Protocol: {result.protocol}")
print(f"Confidence: {result.confidence}")
```

### DePIN Protocol Discovery

For common DePIN protocols with predefined probes:

```python
# Discover common DePIN protocols
result = client.discover_depin_protocols(
    target='192.168.1.100',
    org_id='myorg',
    include_ai=True
)

print(f"Detected: {result.protocol}")
print(f"Evidence: {result.evidence}")
```

### Quick Discovery

For simple use cases:

```python
from pgdn_discovery import discover_node

# Quick discovery with defaults
result = discover_node("192.168.1.100")

if result.success:
    print(f"Found: {result.protocol} (confidence: {result.confidence})")
```

### Available Methods and Tools

```python
# Check available discovery methods
methods = client.get_available_methods()
print("Available methods:", methods)
# Output: {'probe': 'Targeted port/path probing...', 'web': '...', etc.}

# Check available tools
tools = client.get_available_tools()
print("Available tools:", tools)
# Output: {'nmap': 'Network port scanning', 'http_client': '...', etc.}
```

## Discovery Result Format

The `DiscoveryResult` object provides comprehensive information:

```python
@dataclass
class DiscoveryResult:
    success: bool                    # Whether discovery succeeded
    target: str                      # Target IP/hostname
    org_id: Optional[str]           # Organization identifier
    discovery_id: str               # Unique discovery identifier
    timestamp: str                  # ISO timestamp
    duration_seconds: float         # Discovery duration
    enabled_methods: List[str]      # Methods used
    enabled_tools: List[str]        # Tools used
    protocol: Optional[str]         # Detected protocol (if any)
    confidence: float               # Confidence score (0.0-1.0)
    evidence: Dict[str, Any]        # Evidence for detection
    raw_data: Dict[str, Any]        # Raw discovery data
    errors: List[str]               # Any errors encountered
    metadata: Dict[str, Any]        # Additional metadata
```

## CLI Usage

The package includes a command-line interface for standalone usage.

### File Structure Note

- **`cli.py`** - CLI entry point (when package is run as `python -m pgdn_discovery` or via console script)
- **`lib/discovery_client.py`** - Main library API (new professional interface)
- **`lib/discovery.py`** - Legacy discovery functions (backward compatibility)
- **`lib/discovery_components/`** - Core discovery components (probe scanner, AI detector, etc.)

### CLI Commands

```bash
# Legacy discovery mode (backward compatibility)
pgdn-discovery discover 192.168.1.100
pgdn-discovery discover 192.168.1.100 --stage 1 --ports 80,443,9000
pgdn-discovery discover 192.168.1.100 --timeout 30

# Output is JSON format for scripting
pgdn-discovery discover example.com | jq '.result.protocol'
```

The CLI uses the legacy discovery interface for backward compatibility. For new applications, we recommend using the library API directly.

## Configuration Options

### Discovery Methods

- **`probe`** - Targeted port/path probing with nmap integration
- **`web`** - HTTP/HTTPS service detection and analysis
- **`protocol`** - DePIN protocol identification via signatures
- **`ai`** - AI-powered protocol detection (requires API keys)
- **`signature`** - Binary signature matching

### External Tools

- **`nmap`** - Network port scanning
- **`http_client`** - HTTP request processing
- **`tls_analyzer`** - TLS/SSL certificate analysis
- **`banner_grabber`** - Service banner detection

### AI Configuration

For AI-powered analysis, set environment variables:

```bash
export OPENAI_API_KEY="your-openai-key"
# or
export ANTHROPIC_API_KEY="your-anthropic-key"
```

The AI analysis will automatically activate when API keys are available and confidence thresholds are met.

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
import asyncio
from concurrent.futures import ThreadPoolExecutor

def discover_network_range(client, network_base="192.168.1", start=1, end=254):
    """Discover all nodes in a network range"""
    
    def discover_single(ip):
        host = f"{network_base}.{ip}"
        return client.run_discovery(host, org_id="network_scan")
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        hosts = range(start, end + 1)
        results = list(executor.map(discover_single, hosts))
    
    # Filter successful discoveries
    found_nodes = [r for r in results if r.success and r.protocol]
    return found_nodes

# Usage
client = create_discovery_client(timeout=10)
nodes = discover_network_range(client, "192.168.1", 1, 50)
for node in nodes:
    print(f"Found {node.protocol} at {node.target}")
```

### Custom Protocol Detection

```python
# Configure custom probes for specific protocols
custom_probes = [
    {"port": 1234, "path": "/custom/api"},
    {"port": 5678, "path": "/health"},
]

result = client.run_probe_discovery(
    target="192.168.1.100",
    probes=custom_probes,
    org_id="custom_discovery"
)
```

## Development

### Project Structure

```
lib/
├── discovery_client.py       # Main discovery API (new)
├── discovery.py              # Legacy discovery functions
├── discovery_components/     # Core detection components
│   ├── probe_scanner.py     # Two-stage probe scanner
│   ├── ai_detector.py       # AI-powered detection
│   ├── binary_matcher.py    # Protocol matching
│   └── nmap_scanner.py      # Network scanning
└── core/
    └── logging.py           # Logging utilities

cli.py                       # CLI entry point
__init__.py                  # Package exports
setup.py                     # Package setup
requirements.txt             # Dependencies
```

### Adding New Protocols

The modular design allows easy protocol addition:

1. **Add signature patterns** in the appropriate discovery component
2. **Update probe configurations** for new protocol ports/endpoints
3. **Train AI models** with new protocol examples (optional)

### Running Tests

```bash
python tests.py
```

## Migration Guide

### From Legacy API to New API

**Old (Legacy):**
```python
from pgdn_discovery import discover_node
result = discover_node("192.168.1.100")
```

**New (Recommended):**
```python
from pgdn_discovery import create_discovery_client
client = create_discovery_client()
result = client.run_discovery("192.168.1.100")
```

The new API provides:
- Better organization tracking with `org_id`
- Configurable discovery methods and tools
- Structured result objects with full metadata
- Discovery session tracking
- Enhanced error handling

### Backward Compatibility

The legacy API remains available as `legacy_discover_node` for existing code:

```python
from pgdn_discovery import legacy_discover_node
result = legacy_discover_node("192.168.1.100")  # Old format result
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
