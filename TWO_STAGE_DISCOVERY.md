# Two-Stage Discovery Process

This document describes the new two-stage discovery process implemented in PGDN Discovery.

## Overview

The discovery process has been enhanced to support a two-stage approach:

- **Stage 1**: Discovery probe with nmap port scanning and HTTP probing
- **Stage 2**: AI-powered protocol detection

## CLI Usage

### Stage 1: Discovery Probe

Run discovery probes on specific port/path combinations:

```bash
# Basic usage
pgdn-discovery --ip 1.2.3.4 --probes '[{"port":9000,"path":"/metrics"}, {"port":1234,"path":"/rpc/v0"}]'

# With JSON output (same as default)
pgdn-discovery --ip 1.2.3.4 --probes '[{"port":9000,"path":"/metrics"}]' --json
```

### Stage 2: AI Analysis

Run both stages (discovery probe + AI analysis):

```bash
pgdn-discovery --ip 1.2.3.4 --probes '[{"port":9000,"path":"/metrics"}]' --ai
```

### Legacy Mode (Backwards Compatibility)

The original discovery mode is still available:

```bash
pgdn-discovery discover 192.168.1.100
pgdn-discovery discover 192.168.1.100 --stage 1 --ports 80,443,9000
```

## Library Usage

### Python Library Interface

```python
from lib.probe_discovery import probe_services, analyze_with_ai, discover_two_stage

# Stage 1: Discovery probe
probes = [
    {"port": 9000, "path": "/metrics"},
    {"port": 1234, "path": "/rpc/v0"}
]
stage1_result = probe_services("1.2.3.4", probes, timeout=5)

# Stage 2: AI analysis
stage2_result = analyze_with_ai(stage1_result, "1.2.3.4")

# Complete pipeline
full_result = discover_two_stage("1.2.3.4", probes, include_ai=True)
```

### Convenience Functions

```python
from lib.probe_discovery import probe_single_service, probe_common_depin_services

# Probe a single service
result = probe_single_service("1.2.3.4", 9000, "/metrics")

# Probe common DePIN services
result = probe_common_depin_services("1.2.3.4")
```

## Output Format

### Stage 1 Output

```json
{
  "data": [
    {
      "ip": "1.2.3.4",
      "port": 9000,
      "path": "/metrics",
      "status_code": 200,
      "headers": {
        "content-type": "text/plain"
      },
      "body": "consensus_epoch 42\nsui_fullnode 1\n...",
      "matched_banners": ["sui"],
      "error": null,
      "tls_info": {
        "enabled": true,
        "subject": {
          "CN": "node.sui.net"
        },
        "issuer": {
          "CN": "Let's Encrypt"
        }
      }
    },
    {
      "ip": "1.2.3.4",
      "port": 1234,
      "path": "/rpc/v0",
      "status_code": 0,
      "headers": {},
      "body": "",
      "matched_banners": [],
      "error": "connection refused",
      "tls_info": null
    }
  ],
  "error": null,
  "meta": {
    "probe_count": 2,
    "failed": 1,
    "duration_ms": 1203
  },
  "result_type": "success"
}
```

### Stage 2 Output (with AI)

```json
{
  "protocol": "sui",
  "confidence": 0.85,
  "evidence": {
    "ai_analysis": {
      "provider_used": "anthropic",
      "analysis_timestamp": "2024-01-01T12:00:00",
      "discovery_id": 1,
      "hostname": "1.2.3.4"
    },
    "indicators": ["sui_fullnode", "consensus_epoch"]
  },
  "stage1_data": {
    // ... Stage 1 results
  }
}
```

## Implementation Details

### Nmap Integration

Stage 1 uses nmap for port scanning to determine if ports are open before attempting HTTP requests:

- Uses `nmap -p {ports} -T4 -Pn -oX -` for fast scanning
- Parses XML output to determine port states
- Only attempts HTTP probes on open ports

### Banner Matching

The system automatically matches DePIN protocol banners in HTTP responses:

- Checks headers and response body for protocol keywords
- Includes common DePIN protocols: sui, filecoin, ethereum, celestia, bittensor, etc.
- Returns matched banners in the `matched_banners` field

### TLS Information

For HTTPS services, the system extracts TLS certificate information:

- Subject and issuer details
- Certificate validation status
- Available for ports 443, 8443, 9443 by default

### AI Analysis Requirements

Stage 2 AI analysis requires API keys:

- Set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` environment variables
- AI analysis only runs when confidence threshold is met
- Gracefully handles missing API keys

## Error Handling

The system provides detailed error information:

- Connection errors (timeouts, connection refused)
- HTTP errors (4xx, 5xx status codes)  
- Nmap scanning errors
- AI analysis errors

All errors are captured in the appropriate error fields without stopping the overall discovery process. 