"""
Probe Scanner - Two-stage discovery probe system

Stage 1: Discovery probe with nmap port scanning and HTTP probing
"""

import subprocess
import json
import time
import requests
import socket
import ssl
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
import xml.etree.ElementTree as ET


@dataclass
class ProbeResult:
    """Individual probe result"""
    ip: str
    port: int
    path: str
    status_code: int
    headers: Dict[str, str]
    body: str
    matched_banners: List[str]
    error: Optional[str]
    tls_info: Optional[Dict[str, Any]]


@dataclass
class DiscoveryProbeResult:
    """Complete discovery probe result"""
    data: List[ProbeResult]
    error: Optional[str]
    meta: Dict[str, Any]
    result_type: str


class ProbeScanner:
    """High-performance probe scanner with nmap integration"""
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.depin_banners = [
            'sui', 'filecoin', 'ethereum', 'celestia', 'bittensor', 
            'theta', 'akash', 'helium', 'solana', 'avalanche',
            'rpc', 'consensus', 'validator', 'blockchain', 'node'
        ]
    
    def probe_ports_with_nmap(self, ip: str, ports: List[int]) -> Dict[int, str]:
        """
        Runs an nmap scan on the given IP and ports.
        Returns a dict mapping each port to its status: 'open', 'closed', or 'filtered'.
        """
        if not ports:
            return {}
            
        port_list = ",".join(str(p) for p in ports)
        cmd = [
            "nmap",
            "-p", port_list,
            "-T4",  # faster timing
            "-Pn",  # skip ping
            "-oX", "-",  # output as XML to stdout
            ip
        ]
        
        try:
            result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=60)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(f"nmap failed: {e}")

        tree = ET.fromstring(result)
        port_states = {}
        
        # Initialize all ports as unknown
        for port in ports:
            port_states[port] = "unknown"

        # Parse nmap XML output
        for host in tree.findall("host"):
            for ports_el in host.findall("ports"):
                for port in ports_el.findall("port"):
                    port_id = int(port.attrib["portid"])
                    state_elem = port.find("state")
                    if state_elem is not None:
                        state = state_elem.attrib["state"]
                        port_states[port_id] = state

        return port_states
    
    def probe_services(self, ip: str, probes: List[Dict[str, Any]]) -> DiscoveryProbeResult:
        """
        Probe specific services with port/path combinations
        
        Args:
            ip: Target IP address
            probes: List of probe dictionaries with 'port' and 'path' keys
            
        Returns:
            DiscoveryProbeResult with detailed probe information
        """
        start_time = time.time()
        results = []
        failed_count = 0
        
        if not probes:
            return DiscoveryProbeResult(
                data=[],
                error="No probes specified",
                meta={"probe_count": 0, "failed": 0, "duration_ms": 0},
                result_type="error"
            )
        
        # Extract unique ports for nmap scanning
        unique_ports = list(set(probe.get('port') for probe in probes if probe.get('port')))
        
        try:
            # Run nmap port scan first
            port_states = self.probe_ports_with_nmap(ip, unique_ports)
        except Exception as e:
            return DiscoveryProbeResult(
                data=[],
                error=f"nmap scan failed: {str(e)}",
                meta={"probe_count": len(probes), "failed": len(probes), "duration_ms": int((time.time() - start_time) * 1000)},
                result_type="error"
            )
        
        # Probe each service
        for probe in probes:
            port = probe.get('port')
            path = probe.get('path', '/')
            
            if not port:
                failed_count += 1
                results.append(ProbeResult(
                    ip=ip,
                    port=0,
                    path=path,
                    status_code=0,
                    headers={},
                    body="",
                    matched_banners=[],
                    error="Invalid port specified",
                    tls_info=None
                ))
                continue
            
            # Check if port is open from nmap scan
            port_status = port_states.get(port, "unknown")
            
            if port_status != "open":
                failed_count += 1
                results.append(ProbeResult(
                    ip=ip,
                    port=port,
                    path=path,
                    status_code=0,
                    headers={},
                    body="",
                    matched_banners=[],
                    error="connection refused" if port_status == "closed" else f"port {port_status}",
                    tls_info=None
                ))
                continue
            
            # Probe the HTTP service
            probe_result = self._probe_http_service(ip, port, path)
            results.append(probe_result)
            
            if probe_result.error:
                failed_count += 1
        
        duration_ms = int((time.time() - start_time) * 1000)
        
        return DiscoveryProbeResult(
            data=results,
            error=None,
            meta={
                "probe_count": len(probes),
                "failed": failed_count,
                "duration_ms": duration_ms
            },
            result_type="success"
        )
    
    def _probe_http_service(self, ip: str, port: int, path: str) -> ProbeResult:
        """Probe a specific HTTP service"""
        # Try both HTTP and HTTPS
        protocols = ['https', 'http'] if port in [443, 8443, 9443] else ['http', 'https']
        
        for protocol in protocols:
            url = f"{protocol}://{ip}:{port}{path}"
            
            try:
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                    headers={'User-Agent': 'PGDN-Discovery/1.0'}
                )
                
                # Extract TLS info if HTTPS
                tls_info = None
                if protocol == 'https':
                    tls_info = self._get_tls_info(ip, port)
                
                # Match banners in response
                matched_banners = self._match_banners(response.text, response.headers)
                
                return ProbeResult(
                    ip=ip,
                    port=port,
                    path=path,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=response.text,
                    matched_banners=matched_banners,
                    error=None,
                    tls_info=tls_info
                )
                
            except requests.exceptions.RequestException as e:
                # If first protocol fails, try the next one
                if protocol == protocols[-1]:  # Last protocol attempt
                    return ProbeResult(
                        ip=ip,
                        port=port,
                        path=path,
                        status_code=0,
                        headers={},
                        body="",
                        matched_banners=[],
                        error=str(e),
                        tls_info=None
                    )
                continue
        
        # This shouldn't be reached, but just in case
        return ProbeResult(
            ip=ip,
            port=port,
            path=path,
            status_code=0,
            headers={},
            body="",
            matched_banners=[],
            error="unknown error",
            tls_info=None
        )
    
    def _get_tls_info(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Get TLS certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "enabled": True,
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", []))
                    }
        except Exception:
            return None
    
    def _match_banners(self, body: str, headers: Dict[str, str]) -> List[str]:
        """Match DePIN protocol banners in response"""
        matched = []
        body_lower = body.lower()
        
        # Check headers
        for header_name, header_value in headers.items():
            header_lower = f"{header_name} {header_value}".lower()
            for banner in self.depin_banners:
                if banner in header_lower and banner not in matched:
                    matched.append(banner)
        
        # Check body content
        for banner in self.depin_banners:
            if banner in body_lower and banner not in matched:
                matched.append(banner)
        
        return matched
    
    def to_dict(self, result: DiscoveryProbeResult) -> Dict[str, Any]:
        """Convert probe result to dictionary format"""
        data = []
        for probe_result in result.data:
            data.append({
                "ip": probe_result.ip,
                "port": probe_result.port,
                "path": probe_result.path,
                "status_code": probe_result.status_code,
                "headers": probe_result.headers,
                "body": probe_result.body,
                "matched_banners": probe_result.matched_banners,
                "error": probe_result.error,
                "tls_info": probe_result.tls_info
            })
        
        return {
            "data": data,
            "error": result.error,
            "meta": result.meta,
            "result_type": result.result_type
        } 