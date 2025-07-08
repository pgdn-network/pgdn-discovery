"""
PGDN Discovery - Modular Staged Probing Pipeline

A clean, modular library for network probing with staged discovery.
Supports both programmatic and CLI usage.
"""

import json
import socket
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import re

# Optional HTTP functionality
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Default values used across CLI and internal calls
COMMON_PORTS = [80, 443, 8080, 9000, 8545, 30303]
COMMON_ENDPOINTS = ["/", "/metrics", "/health", "/rpc/v0", "/status"]


@dataclass
class DiscoveryResult:
    """Standard discovery result format"""
    ip: str
    open_ports: List[int]
    http_responses: Dict[int, Dict[str, Dict[str, Any]]]
    errors: Dict[str, str]
    timestamp: str
    duration_seconds: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


class NetworkProber:
    """Modular network probing with staged discovery"""
    
    def __init__(self, timeout: int = 5):
        """
        Initialize the prober.
        
        Args:
            timeout: Network timeout in seconds
        """
        self.timeout = timeout
    
    def discover(self, ip: str, stage: str = "all", ports: Optional[List[int]] = None, 
                paths: Optional[List[str]] = None, protocol_filter: Optional[str] = None) -> DiscoveryResult:
        """
        Run staged discovery on target IP.
        
        Args:
            ip: Target IP address
            stage: Discovery stage ("1", "2", or "all")
            ports: List of ports to scan (uses COMMON_PORTS if None)
            paths: List of HTTP paths to check (uses COMMON_ENDPOINTS if None)
            protocol_filter: Optional protocol filter for targeted scanning
            
        Returns:
            DiscoveryResult with structured findings
        """
        start_time = time.time()
        
        # Fast signature-based discovery - no generic port scanning

        result = DiscoveryResult(
            ip=ip,
            open_ports=[],
            http_responses={},
            errors={},
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
            duration_seconds=0.0
        )
        
        try:
            # Simple RPC-based protocol discovery
            protocol_result = self._discover_protocol(ip, protocol_filter)
            
            if protocol_result:
                # Extract port from endpoint URL
                endpoint = protocol_result["endpoint"]
                port = int(endpoint.split(':')[-1]) if ':' in endpoint else (443 if 'https' in endpoint else 80)
                
                result.open_ports = [port]
                result.http_responses = {
                    port: {
                        "/": {
                            "status_code": 200,
                            "protocol": protocol_result["protocol"],
                            "endpoint": endpoint
                        }
                    }
                }
        
        except Exception as e:
            result.errors["discovery"] = str(e)
        
        result.duration_seconds = round(time.time() - start_time, 2)
        return result
    
    def _port_scan(self, ip: str, ports: List[int]) -> List[int]:
        """
        Perform TCP connect scan on specified ports.
        
        Args:
            ip: Target IP address
            ports: List of ports to scan
            
        Returns:
            List of open ports
        """
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    
            except Exception:
                # Silently continue on port scan errors
                continue
        
        return open_ports
    
    
    def _parse_http_payload(self, payload: str) -> Tuple[str, str, Dict[str, str], str]:
        """
        Parse raw HTTP payload into method, path, headers, and body.
        
        Args:
            payload: Raw HTTP request payload
            
        Returns:
            Tuple of (method, path, headers, body)
        """
        # Split on literal CRLF sequences
        lines = payload.split('\\r\\n')
        if not lines:
            return "GET", "/", {}, ""
        
        # Parse request line
        request_line = lines[0]
        parts = request_line.split(' ')
        if len(parts) >= 3:
            method = parts[0]
            path = parts[1]
        else:
            method = "GET"
            path = "/"
        
        # Parse headers - find empty line that separates headers from body
        headers = {}
        body_start = len(lines)
        
        for i in range(1, len(lines)):
            line = lines[i]
            if line.strip() == "":
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # Parse body (everything after empty line)
        body_lines = lines[body_start:] if body_start < len(lines) else []
        body = '\\r\\n'.join(body_lines)
        
        return method, path, headers, body
    
    def _discover_protocol(self, ip: str, protocol_filter: Optional[str] = None) -> Optional[Dict[str, str]]:
        """
        Simple RPC-based protocol discovery.
        
        Args:
            ip: Target IP address
            protocol_filter: Optional protocol filter
            
        Returns:
            Dictionary with protocol and endpoint if found, None otherwise
        """
        if not HAS_REQUESTS:
            return None
        
        try:
            import yaml
            from pathlib import Path
        except ImportError:
            return None
        
        # Load protocol configs
        try:
            current_dir = Path(__file__).parent
            signatures_dir = current_dir / "signatures"
            
            for yaml_file in signatures_dir.glob("*.yaml"):
                protocol_name = yaml_file.stem
                
                # Apply protocol filter
                if protocol_filter and protocol_name != protocol_filter:
                    continue
                
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                
                # Test ports in probability order (early exit on success)
                for port in config.get('ports', []):
                    try:
                        # Determine protocol (HTTP vs HTTPS)
                        https_ports = [443, 8443, 9443]
                        protocol = "https" if port in https_ports else "http"
                        url = f"{protocol}://{ip}:{port}"
                        
                        # Make RPC call
                        response = requests.post(url, json={
                            "jsonrpc": "2.0",
                            "method": config.get('rpc_method'),
                            "params": [],
                            "id": 1
                        }, timeout=self.timeout, verify=False)
                        
                        # Check for successful RPC response
                        if response.status_code == 200:
                            try:
                                json_response = response.json()
                                if "result" in json_response:
                                    # SUCCESS: Return immediately
                                    return {
                                        "protocol": protocol_name,
                                        "endpoint": url
                                    }
                            except:
                                continue
                                
                    except:
                        continue  # Silent failure, try next port
                        
        except Exception:
            pass
        
        return None
    
    def _web_scan(self, ip: str, ports: List[int], paths: List[str]) -> Dict[int, Dict[str, Dict[str, Any]]]:
        """
        Perform HTTP requests - now supports both generic scanning and signature probes.
        
        Args:
            ip: Target IP address
            ports: List of ports to scan
            paths: List of HTTP paths to check
            
        Returns:
            Dictionary mapping port -> path -> response data
        """
        # Use signature-aware probing by default
        return self._execute_signature_probes(ip)


def discover_node(ip: str, stage: str = "all", ports: Optional[List[int]] = None, 
                 paths: Optional[List[str]] = None, timeout: int = 5) -> Dict[str, Any]:
    """
    Convenience function for network discovery.
    
    Args:
        ip: Target IP address
        stage: Discovery stage ("1", "2", or "all")
        ports: List of ports to scan (uses COMMON_PORTS if None)
        paths: List of HTTP paths to check (uses COMMON_ENDPOINTS if None)
        timeout: Network timeout in seconds
        
    Returns:
        Discovery result as dictionary
    """
    prober = NetworkProber(timeout=timeout)
    result = prober.discover(ip, stage, ports, paths)
    return result.to_dict()


if __name__ == "__main__":
    # Simple test
    result = discover_node("127.0.0.1", stage="1", ports=[22, 80, 443])
    print(json.dumps(result, indent=2))
