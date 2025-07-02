# Protocol Signature System

## Overview

The PGDN Discovery system now uses a sophisticated YAML-based protocol signature matching system that replaces the previous simple banner matching. This solves the issue where protocols sharing similar ports (like Sui and Walrus) were being confused.

## How It Works

### 1. YAML-Based Signatures

Protocol signatures are now defined in YAML files located in `pgdn_discovery/signatures/`. Each protocol has its own YAML file with:

- **Protocol metadata**: Name, network type, default ports
- **Probe definitions**: Specific HTTP requests to test the protocol
- **Signature patterns**: Regex patterns that uniquely identify the protocol

### 2. Signature Matching Process

1. **Load signatures**: All YAML files are loaded at startup
2. **Port filtering**: Only check signatures for protocols that use the detected port
3. **Pattern matching**: Apply regex patterns to response headers and body
4. **Confidence scoring**: Calculate confidence based on pattern specificity
5. **Deduplication**: Handle multiple matches and boost confidence for multiple signature hits

### 3. Confidence Scoring

- **0.95+**: Highly specific patterns (version strings, unique API responses)
- **0.85-0.94**: Protocol-specific patterns (metrics, RPC methods)
- **0.70-0.84**: General but reliable patterns (health checks, headers)
- **<0.70**: Weak patterns (generic keywords)

## Signature File Format

```yaml
name: "Protocol Name"
network_type: "blockchain|storage|compute"
default_ports: [8080, 9000, 31415]

probes:
  - name: PROBE_NAME
    payload: "GET /path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    ports: [8080]
    requires_ssl: false

signatures:
  - label: "Signature Description"
    regex: 'pattern_to_match'
    version_group: ver  # Optional: capture group name for version
```

## Example: Sui vs Walrus Disambiguation

### Problem
Both Sui and Walrus can run on similar ports, causing false positives:
- Sui: ports 9000, 9184 (metrics, RPC)
- Walrus: ports 8080, 31415 (API, storage)

### Solution
Different signature patterns:

**Sui signatures:**
```yaml
signatures:
  - label: "Sui Node"
    regex: 'sui_node_build_info.*version="(?P<ver>[^"]+)"'
  - label: "Sui RPC"
    regex: '"result":\s*"(?P<ver>[\d.]+)".*sui_getRpcApiVersion'
  - label: "Sui Validator"
    regex: 'sui_validator_.*|sui_consensus_'
```

**Walrus signatures:**
```yaml
signatures:
  - label: "Walrus Storage Node"
    regex: '"walrus".*"version":\s*"(?P<ver>[^"]+)"'
  - label: "Walrus Headers"
    regex: 'x-walrus-|walrus-version|walrus-node-id'
  - label: "Walrus Network ID"
    regex: '"network":\s*"walrus"|"protocol":\s*"walrus"'
```

## Adding New Protocols

1. Create a new YAML file in `pgdn_discovery/signatures/protocol_name.yaml`
2. Define the protocol metadata, probes, and signatures
3. The system will automatically load it on startup

Example template:
```yaml
name: "My Protocol"
network_type: "blockchain"
default_ports: [8080, 9000]

probes:
  - name: VERSION_CHECK
    payload: "GET /version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    ports: [8080]
    requires_ssl: false

signatures:
  - label: "Protocol Version"
    regex: '"my_protocol".*"version":\s*"(?P<ver>[^"]+)"'
    version_group: ver
```

## Testing

Run the comprehensive test to verify signature matching:

```bash
python test_yaml_signatures.py
```

This tests:
- YAML signature loading
- Correct protocol identification
- Overlapping port disambiguation
- False positive prevention

## Benefits

1. **Accuracy**: Higher precision protocol identification
2. **Maintainability**: Easy to add/modify protocols via YAML
3. **Extensibility**: Simple to add new signature types
4. **Debugging**: Clear confidence scores and evidence trails
5. **Performance**: Efficient regex-based matching with port filtering
