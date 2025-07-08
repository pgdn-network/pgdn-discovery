"""
PGDN Discovery - Modular Staged Probing Pipeline

A clean, modular library for network probing with staged discovery.
Supports both programmatic and CLI usage.
"""

import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

# Optional HTTP functionality
try:
    import requests
    HAS_REQUESTS = True
    
    # Suppress SSL warnings for unverified HTTPS requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    HAS_REQUESTS = False



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


class ProtocolDiscoverer:
    """Modular protocol discovery with staged probing"""
    
    def __init__(self, timeout: int = 5):
        """
        Initialize the discoverer.
        
        Args:
            timeout: Network timeout in seconds
        """
        self.timeout = timeout
    
    def discover(self, ip: str, stage: str = "all", ports: Optional[List[int]] = None, 
                paths: Optional[List[str]] = None, protocol_filter: Optional[str] = None) -> DiscoveryResult:
        """
        Run protocol discovery (both RPC and HTTP-based).
        
        Args:
            ip: Target IP address
            protocol_filter: Optional protocol filter for targeted scanning
            
        Returns:
            DiscoveryResult with structured findings
        """
        start_time = time.time()
        
        result = DiscoveryResult(
            ip=ip,
            open_ports=[],
            http_responses={},
            errors={},
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
            duration_seconds=0.0
        )
        
        try:
            # Discover both RPC and HTTP protocols
            rpc_results = self._discover_rpc_protocol(ip, protocol_filter)
            http_results = self._discover_http_protocol(ip, protocol_filter)
            
            # Combine results from both discovery methods
            all_results = rpc_results + http_results
            
            if all_results:
                for protocol_result in all_results:
                    endpoint = protocol_result["endpoint"]
                    port = int(endpoint.split(':')[-1]) if ':' in endpoint else (443 if 'https' in endpoint else 80)
                    
                    if port not in result.open_ports:
                        result.open_ports.append(port)
                    
                    if port not in result.http_responses:
                        result.http_responses[port] = {}
                    
                    result.http_responses[port]["/"] = {
                        "status_code": 200,
                        "protocol": protocol_result["protocol"],
                        "endpoint": endpoint
                    }
        
        except Exception as e:
            result.errors["discovery"] = str(e)
        
        result.duration_seconds = round(time.time() - start_time, 2)
        return result
    
    
    
    
    def _discover_rpc_protocol(self, ip: str, protocol_filter: Optional[str] = None) -> List[Dict[str, str]]:
        """
        RPC-based protocol discovery - finds protocols using JSON-RPC methods.
        
        Args:
            ip: Target IP address
            protocol_filter: Optional protocol filter
            
        Returns:
            List of dictionaries with protocol and endpoint info
        """
        found_protocols = []
        
        if not HAS_REQUESTS:
            return found_protocols
        
        try:
            import yaml
            from pathlib import Path
        except ImportError:
            return found_protocols
        
        try:
            current_dir = Path(__file__).parent
            signatures_file = current_dir / "signatures.yaml"
            
            if not signatures_file.exists():
                return found_protocols
            
            with open(signatures_file, 'r', encoding='utf-8') as f:
                signatures_data = yaml.safe_load(f)
            
            protocols = signatures_data.get('protocols', {})
            
            # Validate protocol filter if provided
            if protocol_filter:
                if protocol_filter not in protocols:
                    # Protocol not found in signatures - return empty list
                    return found_protocols
                # Only scan the specified protocol
                protocols_to_scan = {protocol_filter: protocols[protocol_filter]}
            else:
                # Scan all protocols
                protocols_to_scan = protocols
            
            for protocol_name, config in protocols_to_scan.items():
                # Only process protocols with rpc_method (RPC-based)
                if 'rpc_method' not in config:
                    continue
                    
                for port in config.get('ports', []):
                    try:
                        https_ports = [443, 8443, 9443]
                        protocol = "https" if port in https_ports else "http"
                        url = f"{protocol}://{ip}:{port}"
                        
                        response = requests.post(url, json={
                            "jsonrpc": "2.0",
                            "method": config.get('rpc_method'),
                            "params": [],
                            "id": 1
                        }, timeout=self.timeout, verify=False)
                        
                        if response.status_code == 200:
                            try:
                                json_response = response.json()
                                if "result" in json_response:
                                    found_protocols.append({
                                        "protocol": protocol_name,
                                        "endpoint": url
                                    })
                                    # Exit early if we've found 3 protocols (max supported)
                                    if len(found_protocols) >= 3:
                                        return found_protocols
                                    break  # Found this protocol, try next protocol
                            except:
                                continue
                                
                    except:
                        continue
                        
        except Exception:
            pass
        
        return found_protocols
    
    def _discover_http_protocol(self, ip: str, protocol_filter: Optional[str] = None) -> List[Dict[str, str]]:
        """
        HTTP-based protocol discovery - finds protocols using HTTP GET requests.
        
        Args:
            ip: Target IP address
            protocol_filter: Optional protocol filter
            
        Returns:
            List of dictionaries with protocol and endpoint info
        """
        found_protocols = []
        
        if not HAS_REQUESTS:
            return found_protocols
        
        try:
            import yaml
            from pathlib import Path
        except ImportError:
            return found_protocols
        
        try:
            current_dir = Path(__file__).parent
            signatures_file = current_dir / "signatures.yaml"
            
            if not signatures_file.exists():
                return found_protocols
            
            with open(signatures_file, 'r', encoding='utf-8') as f:
                signatures_data = yaml.safe_load(f)
            
            protocols = signatures_data.get('protocols', {})
            
            # Validate protocol filter if provided
            if protocol_filter:
                if protocol_filter not in protocols:
                    # Protocol not found in signatures - return empty list
                    return found_protocols
                # Only scan the specified protocol
                protocols_to_scan = {protocol_filter: protocols[protocol_filter]}
            else:
                # Scan all protocols
                protocols_to_scan = protocols
            
            for protocol_name, config in protocols_to_scan.items():
                # Only process protocols with api_method (HTTP-based)
                if 'api_method' not in config:
                    continue
                    
                for port in config.get('ports', []):
                    if self._probe_http_node(ip, port, config.get('api_method'), self.timeout):
                        https_ports = [443, 8443, 9443]
                        protocol = "https" if port in https_ports else "http"
                        url = f"{protocol}://{ip}:{port}"
                        
                        found_protocols.append({
                            "protocol": protocol_name,
                            "endpoint": url
                        })
                        
                        # Exit early if we've found 3 protocols (max supported)
                        if len(found_protocols) >= 3:
                            return found_protocols
                        break  # Found this protocol, try next protocol
                        
        except Exception:
            pass
        
        return found_protocols
    
    def _probe_http_node(self, host: str, port: int, api_method: str, timeout: int) -> bool:
        """
        Probes an HTTP node by calling a specific API method.
        
        Args:
            host: Hostname or IP address
            port: Port number
            api_method: API method to call (e.g., 'getValidators')
            timeout: Timeout in seconds
            
        Returns:
            True if node responds correctly, False otherwise.
        """
        https_ports = [443, 8443, 9443]
        protocol = "https" if port in https_ports else "http"
        url = f"{protocol}://{host}:{port}/v1/api?{api_method}"
        
        try:
            response = requests.get(url, timeout=timeout, verify=False)
            if response.status_code == 200:
                try:
                    data = response.json()
                    # For Walrus, check for 'validators' key
                    if api_method == "getValidators" and "validators" in data:
                        return True
                    # For other API methods, just check if we get valid JSON
                    elif api_method != "getValidators" and data:
                        return True
                except:
                    pass
        except:
            pass
        
        return False
    


def discover_node(ip: str, timeout: int = 5, protocol_filter: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function for protocol discovery (both RPC and HTTP-based).
    
    Args:
        ip: Target IP address
        timeout: Network timeout in seconds
        protocol_filter: Optional protocol filter
        
    Returns:
        Discovery result as dictionary
    """
    discoverer = ProtocolDiscoverer(timeout=timeout)
    result = discoverer.discover(ip, protocol_filter=protocol_filter)
    return result.to_dict()


if __name__ == "__main__":
    # Simple test
    result = discover_node("127.0.0.1", timeout=5)
    print(result)
