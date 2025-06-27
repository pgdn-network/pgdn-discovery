"""
PGDN Discovery - Modular Staged Probing Pipeline

A clean, modular library for network probing with staged discovery.
Supports both programmatic and CLI usage.
"""

import json
import socket
import ssl
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

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
    tls_info: Dict[int, Dict[str, Any]]
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
                paths: Optional[List[str]] = None) -> DiscoveryResult:
        """
        Run staged discovery on target IP.
        
        Args:
            ip: Target IP address
            stage: Discovery stage ("1", "2", or "all")
            ports: List of ports to scan (uses COMMON_PORTS if None)
            paths: List of HTTP paths to check (uses COMMON_ENDPOINTS if None)
            
        Returns:
            DiscoveryResult with structured findings
        """
        start_time = time.time()
        
        # Use defaults if not provided
        if ports is None:
            ports = COMMON_PORTS.copy()
        if paths is None:
            paths = COMMON_ENDPOINTS.copy()
        
        result = DiscoveryResult(
            ip=ip,
            open_ports=[],
            http_responses={},
            tls_info={},
            errors={},
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
            duration_seconds=0.0
        )
        
        try:
            # Stage 1: Port scan
            if stage in ["1", "all"]:
                result.open_ports = self._port_scan(ip, ports)
                result.tls_info = self._get_tls_info(ip, result.open_ports)
            
            # Stage 2: Web scan
            if stage in ["2", "all"]:
                if not result.open_ports and stage == "2":
                    # If only doing stage 2, assume all provided ports are open
                    result.open_ports = ports
                result.http_responses = self._web_scan(ip, result.open_ports, paths)
        
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
    
    def _get_tls_info(self, ip: str, ports: List[int]) -> Dict[int, Dict[str, Any]]:
        """
        Get TLS certificate information for HTTPS ports.
        
        Args:
            ip: Target IP address
            ports: List of open ports to check
            
        Returns:
            Dictionary mapping port to TLS info
        """
        tls_info = {}
        
        # Common HTTPS ports
        https_ports = [443, 8443, 9443]
        
        for port in ports:
            if port in https_ports:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=ip) as ssock:
                            cert = ssock.getpeercert()
                            tls_info[port] = {
                                "subject": dict(x[0] for x in cert.get("subject", [])),
                                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                                "version": cert.get("version"),
                                "serial_number": str(cert.get("serialNumber", "")),
                                "not_before": cert.get("notBefore"),
                                "not_after": cert.get("notAfter")
                            }
                            
                except Exception as e:
                    tls_info[port] = {"error": str(e)}
        
        return tls_info
    
    def _web_scan(self, ip: str, ports: List[int], paths: List[str]) -> Dict[int, Dict[str, Dict[str, Any]]]:
        """
        Perform HTTP GET requests on specified ports and paths.
        
        Args:
            ip: Target IP address
            ports: List of ports to scan
            paths: List of HTTP paths to check
            
        Returns:
            Dictionary mapping port -> path -> response data
        """
        if not HAS_REQUESTS:
            return {"error": "requests library not available for HTTP scanning"}
        
        responses = {}
        
        # Common HTTP ports
        http_ports = [80, 8080, 8000, 9000]
        https_ports = [443, 8443, 9443]
        
        for port in ports:
            responses[port] = {}
            
            # Determine protocol
            if port in https_ports:
                protocol = "https"
            elif port in http_ports or port in [80, 443]:  # Include standard ports
                protocol = "https" if port == 443 else "http"
            else:
                # Try both protocols for unknown ports
                protocol = "http"
            
            for path in paths:
                url = f"{protocol}://{ip}:{port}{path}"
                
                try:
                    response = requests.get(
                        url, 
                        timeout=self.timeout, 
                        verify=False,
                        allow_redirects=False
                    )
                    
                    responses[port][path] = {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "body": response.text[:1000],  # First 1000 chars
                        "body_length": len(response.text)
                    }
                    
                except Exception as e:
                    # If HTTP fails and we haven't tried HTTPS, try HTTPS
                    if protocol == "http" and port not in http_ports:
                        https_url = f"https://{ip}:{port}{path}"
                        try:
                            response = requests.get(
                                https_url, 
                                timeout=self.timeout, 
                                verify=False,
                                allow_redirects=False
                            )
                            
                            responses[port][path] = {
                                "status_code": response.status_code,
                                "headers": dict(response.headers),
                                "body": response.text[:1000],
                                "body_length": len(response.text)
                            }
                            continue
                            
                        except Exception:
                            pass
                    
                    responses[port][path] = {"error": str(e)}
        
        return responses


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
