# PGDN Discovery

A fast, simple Python library for discovering DePIN (Decentralized Physical Infrastructure Network) protocols on network nodes using both RPC-based and HTTP-based detection. Built for speed and reliability with early exit optimization.

You should not be using this library without consent from the Sui network operators. This tool is intended for educational and research purposes only.

## Features

- 🚀 **Fast Protocol Detection**: Direct JSON-RPC calls and HTTP requests for instant protocol identification
- 🎯 **Early Exit**: Stops scanning immediately upon finding protocols (max 3 supported)
- 📊 **Structured Results**: Consistent JSON format with data arrays and error blocks
- 🔧 **Easy Protocol Addition**: Simple YAML configuration for new protocols
- 🎛️ **Protocol Filtering**: Scan specific protocols or discover all available
- 📋 **Validation**: Built-in protocol validation with helpful error messages
- ⚡ **Probability Ordering**: Tests most likely ports first for faster detection

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

### Basic Protocol Discovery

```python
from pgdn_discovery import ProtocolDiscoverer

# Create discoverer instance
discoverer = ProtocolDiscoverer(timeout=10)

# Discover all protocols on a node
result = discoverer.discover("fullnode.mainnet.sui.io")
print(f"Found protocols: {result.open_ports}")
print(f"HTTP responses: {result.http_responses}")
```

### Convenience Function

```python
from pgdn_discovery import discover_node

# Quick discovery with default settings
result = discover_node("fullnode.mainnet.sui.io", timeout=15)
print(f"Discovery result: {result}")

# With protocol filter
result = discover_node("fullnode.mainnet.sui.io", protocol_filter="sui")
print(f"Sui discovery: {result}")
```

### Working with Results

```python
from pgdn_discovery import ProtocolDiscoverer

discoverer = ProtocolDiscoverer(timeout=10)
result = discoverer.discover("fullnode.mainnet.sui.io")

# Access discovery results
print(f"Target: {result.ip}")
print(f"Duration: {result.duration_seconds}s")
print(f"Timestamp: {result.timestamp}")

# Check for protocols found
if result.open_ports:
    for port in result.open_ports:
        if port in result.http_responses:
            response = result.http_responses[port]["/"]
            print(f"Protocol: {response['protocol']}")
            print(f"Endpoint: {response['endpoint']}")

# Check for errors
if result.errors:
    print(f"Errors: {result.errors}")
```

## CLI Usage

### Discover All Protocols

```bash
# Discover all protocols on a node
pgdn-discovery discover fullnode.mainnet.sui.io

# With custom timeout
pgdn-discovery discover fullnode.mainnet.sui.io --timeout 15
```

### Protocol-Specific Discovery

```bash
# Discover only Sui protocol
pgdn-discovery discover fullnode.mainnet.sui.io --protocol sui

# Discover only Ethereum protocol
pgdn-discovery discover eth-mainnet.example.com --protocol ethereum
```

### CLI Response Format

**Success Response:**
```json
{"data": [{"protocol": "sui", "endpoint": "https://fullnode.mainnet.sui.io:443"}]}
```

**No Results:**
```json
{"data": []}
```

**Error Response:**
```json
{"error": "Protocol 'invalid' not found in signatures"}
```

### Alternative CLI Usage

```bash
# Use as Python module
python -m pgdn_discovery discover fullnode.mainnet.sui.io --protocol sui

# Use wrapper script
python cli.py discover fullnode.mainnet.sui.io --protocol sui
```

## Protocol Configuration

Protocols are defined in `pgdn_discovery/signatures.yaml`:

```yaml
protocols:
  sui:
    name: "Sui"
    rpc_method: "sui_getChainIdentifier"
    ports: [443, 9000, 9184]
  
  ethereum:
    name: "Ethereum"
    rpc_method: "eth_chainId"
    ports: [8545, 443, 80]
  
  walrus:
    name: "Walrus"
    api_method: "getValidators"
    ports: [443]
    http_method: "GET"
```

### Adding New Protocols

Add new protocol definitions to the `signatures.yaml` file:

**For RPC-based protocols:**
```yaml
protocols:
  your_rpc_protocol:
    name: "Your RPC Protocol"
    rpc_method: "your_rpc_method"
    ports: [8080, 443, 9000]
```

**For HTTP-based protocols:**
```yaml
protocols:
  your_http_protocol:
    name: "Your HTTP Protocol"
    api_method: "your_api_method"
    ports: [443, 8080]
    http_method: "GET"
```

The system will automatically:
- Validate protocol names when using `--protocol` filter
- Test ports in the specified order (probability-based)
- Make JSON-RPC calls (for `rpc_method`) or HTTP requests (for `api_method`) to detect the protocol
- Return results immediately when found

## Discovery Result Format

The `DiscoveryResult` object provides comprehensive information:

```python
@dataclass
class DiscoveryResult:
    ip: str                          # Target IP address
    open_ports: List[int]           # List of open ports found
    http_responses: Dict[int, Dict[str, Dict[str, Any]]]  # Port -> Path -> Response data
    errors: Dict[str, str]          # Any errors encountered
    timestamp: str                  # ISO timestamp
    duration_seconds: float         # Discovery duration
    
    def to_dict(self) -> Dict[str, Any]:  # Convert to dictionary
        return asdict(self)
```

## Supported Protocols

Currently supports these DePIN protocols:

**RPC-based protocols:**
- **Sui** - Full nodes and validators (`sui_getChainIdentifier`)
- **Ethereum** - Execution clients (`eth_chainId`)

**HTTP-based protocols:**
- **Walrus** - Aggregator nodes (`getValidators` API)

More protocols can be easily added by updating the `signatures.yaml` file with appropriate RPC methods (for RPC-based) or API methods (for HTTP-based) and ports.

## Performance Features

### Early Exit Optimization
- Stops scanning after finding 3 protocols (current maximum supported)
- Tests ports in probability order for faster detection
- Immediate return on successful RPC response

### Efficient Scanning
- Direct RPC calls and HTTP requests (no port scanning or banner grabbing)
- Concurrent protocol testing
- Configurable timeouts for different network conditions

### Example Performance
```python
import time
from pgdn_discovery import ProtocolDiscoverer

discoverer = ProtocolDiscoverer(timeout=5)

start_time = time.time()
result = discoverer.discover("fullnode.mainnet.sui.io")
end_time = time.time()

print(f"Discovery completed in {end_time - start_time:.2f}s")
print(f"Found {len(result.open_ports)} protocols")
```

## Development

### Running Tests

```bash
# Test CLI functionality
python cli.py discover fullnode.mainnet.sui.io --protocol sui

# Test library functionality
python -c "from pgdn_discovery import discover_node; print(discover_node('fullnode.mainnet.sui.io'))"

# Test with module execution
python -m pgdn_discovery discover fullnode.mainnet.sui.io --protocol sui
```

### Package Structure

```
pgdn_discovery/
├── __init__.py          # Main package exports
├── __main__.py          # Module execution entry point
├── cli.py               # CLI implementation
├── discovery.py         # Core ProtocolDiscoverer class
└── signatures.yaml      # Protocol definitions

cli.py                   # CLI wrapper script
setup.py                 # Package configuration
```

## API Reference

### ProtocolDiscoverer Class

```python
class ProtocolDiscoverer:
    def __init__(self, timeout: int = 5):
        """Initialize with custom timeout"""
        
    def discover(self, ip: str, protocol_filter: Optional[str] = None) -> DiscoveryResult:
        """Discover protocols on target IP"""
```

### Convenience Functions

```python
def discover_node(ip: str, timeout: int = 5, protocol_filter: Optional[str] = None) -> Dict[str, Any]:
    """Convenience function returning dictionary result"""
```

### CLI Functions

```python
def discover_protocols(ip: str, timeout: int = 5, protocol_filter: Optional[str] = None) -> Dict[str, Any]:
    """CLI discovery function with structured JSON response"""
```

## Error Handling

The system handles errors gracefully:

```python
from pgdn_discovery import ProtocolDiscoverer

discoverer = ProtocolDiscoverer(timeout=5)
result = discoverer.discover("invalid.host.com")

if result.errors:
    print(f"Discovery errors: {result.errors}")
else:
    print(f"Discovery successful: {result.open_ports}")
```

CLI errors are returned as JSON:
```json
{"error": "Connection timeout"}
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with existing protocols
5. Submit a pull request

## Support

- 📧 Email: team@pgdn.network
- 🐛 Issues: [GitHub Issues](https://github.com/pgdn-network/pgdn-discovery/issues)
- 📖 Documentation: [GitHub Wiki](https://github.com/pgdn-network/pgdn-discovery/wiki)
