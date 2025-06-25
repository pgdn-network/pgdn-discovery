"""
PGDN Discover - Simple DePIN Protocol Discovery Library

A lightweight library for discovering DePIN protocols on network nodes.
No database dependencies, agent architecture, or complex orchestration.
Returns results as JSON objects.
"""

import json
import subprocess
import requests
import logging
import socket
import re
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
import xml.etree.ElementTree as ET

# Import discovery components
from .discovery_components.ai_detector import AIServiceDetector
from .discovery_components.nmap_scanner import NmapScanner
from .discovery_components.binary_matcher import HighPerformanceBinaryMatcher
from .core.logging import setup_logging, get_logger


class ConfidenceLevel(Enum):
    """Confidence levels for protocol detection"""
    HIGH = "high"
    MEDIUM = "medium" 
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class DiscoveryResult:
    """Result structure for protocol discovery"""
    protocol: Optional[str]
    confidence: str
    confidence_score: float
    evidence: Dict[str, Any]
    scan_data: Dict[str, Any]
    signature_match: Optional[Dict[str, Any]] = None
    performance_metrics: Optional[Dict[str, Any]] = None
    host: Optional[str] = None
    timestamp: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


class ProtocolDiscovery:
    """Simple protocol discovery implementation"""
    
    def __init__(self, timeout: int = 30, debug: bool = False):
        """
        Initialize discovery with basic configuration.
        
        Args:
            timeout: Network timeout in seconds
            debug: Enable debug logging
        """
        self.timeout = timeout
        self.debug = debug
        self.logger = setup_logging("DEBUG" if debug else "INFO", debug)
        
        # Initialize discovery components
        try:
            self.ai_detector = AIServiceDetector()
            self.nmap_scanner = NmapScanner()
            self.binary_matcher = HighPerformanceBinaryMatcher()
        except Exception as e:
            self.logger.warning(f"Some discovery components failed to initialize: {e}")
            self.ai_detector = None
            self.nmap_scanner = None
            self.binary_matcher = None
        
        # Basic protocol signatures
        self.protocol_signatures = {
            'sui': {
                'ports': [9000, 8080, 8084],
                'endpoints': ['/metrics', '/health'],
                'content_patterns': ['sui', 'consensus_epoch', 'fullnode'],
                'headers': ['sui-rpc-version']
            },
            'filecoin': {
                'ports': [1234, 3453, 8080],
                'endpoints': ['/rpc/v0', '/api/v0/id'],
                'content_patterns': ['lotus', 'filecoin', 'miner_id'],
                'headers': ['lotus-gateway']
            },
            'ethereum': {
                'ports': [8545, 8546, 30303],
                'endpoints': ['/'],
                'content_patterns': ['ethereum', 'geth', 'eth_'],
                'rpc_methods': ['eth_blockNumber', 'net_version']
            }
        }
    
    def _setup_logger(self) -> logging.Logger:
        """Set up basic logging"""
        logger = logging.getLogger('pgdn_discover')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger
    
    def discover_node(self, host: str, node_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Discover protocol for a given host.
        
        Args:
            host: Target host IP/hostname
            node_id: Optional node identifier
            
        Returns:
            Discovery result as dictionary
        """
        start_time = time.time()
        self.logger.info(f"Starting protocol discovery for {host}")
        
        try:
            # Perform network scan
            scan_data = self._perform_network_scan(host)
            
            # Analyze for protocol patterns
            result = self._analyze_protocol(host, scan_data)
            
            # Add metadata
            result.host = host
            result.timestamp = datetime.utcnow().isoformat()
            result.performance_metrics = {
                'discovery_time_seconds': round(time.time() - start_time, 2),
                'scanned_ports': len(scan_data.get('open_ports', [])),
                'http_endpoints_checked': len(scan_data.get('http_responses', {}))
            }
            
            self.logger.info(f"Discovery completed for {host}: {result.protocol} ({result.confidence})")
            
            return {
                'success': True,
                'operation': 'discovery',
                'host': host,
                'node_id': node_id,
                'result': result.to_dict()
            }
            
        except Exception as e:
            self.logger.error(f"Discovery failed for {host}: {str(e)}")
            return {
                'success': False,
                'operation': 'discovery',
                'host': host,
                'node_id': node_id,
                'error': str(e),
                'execution_time_seconds': round(time.time() - start_time, 2)
            }
    
    def _perform_network_scan(self, host: str) -> Dict[str, Any]:
        """Perform basic network scanning"""
        scan_data = {
            'open_ports': [],
            'http_responses': {},
            'tcp_banners': {},
            'host_info': {}
        }
        
        # Basic port scan
        common_ports = [22, 80, 443, 1234, 3453, 8080, 8084, 8545, 8546, 9000, 30303]
        
        for port in common_ports:
            if self._check_port(host, port):
                scan_data['open_ports'].append(port)
                
                # Get TCP banner if possible
                banner = self._get_tcp_banner(host, port)
                if banner:
                    scan_data['tcp_banners'][port] = banner
                
                # Try HTTP if on common HTTP ports
                if port in [80, 443, 8080, 8084, 8545]:
                    http_data = self._check_http_endpoints(host, port)
                    if http_data:
                        scan_data['http_responses'][port] = http_data
        
        return scan_data
    
    def _check_port(self, host: str, port: int) -> bool:
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _get_tcp_banner(self, host: str, port: int) -> Optional[str]:
        """Get TCP banner from a port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            
            # Send minimal probe
            sock.send(b'GET / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return banner.strip()[:500]  # Limit banner size
        except:
            return None
    
    def _check_http_endpoints(self, host: str, port: int) -> Dict[str, Any]:
        """Check HTTP endpoints for protocol indicators"""
        http_data = {}
        
        protocol = 'https' if port == 443 else 'http'
        base_url = f"{protocol}://{host}:{port}"
        
        # Common endpoints to check
        endpoints = ['/', '/metrics', '/health', '/rpc/v0', '/api/v0/id']
        
        for endpoint in endpoints:
            try:
                url = f"{base_url}{endpoint}"
                response = requests.get(url, timeout=5, verify=False)
                
                http_data[endpoint] = {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'content_snippet': response.text[:1000],  # First 1000 chars
                    'content_length': len(response.text)
                }
                
            except Exception as e:
                http_data[endpoint] = {
                    'error': str(e)
                }
        
        return http_data
    
    def _analyze_protocol(self, host: str, scan_data: Dict[str, Any]) -> DiscoveryResult:
        """Analyze scan data to determine protocol"""
        
        protocol_scores = {}
        evidence = {
            'port_matches': {},
            'content_matches': {},
            'header_matches': {},
            'banner_matches': {}
        }
        
        # Score each protocol based on evidence
        for protocol_name, signature in self.protocol_signatures.items():
            score = 0
            
            # Check port matches
            port_matches = []
            for port in signature['ports']:
                if port in scan_data['open_ports']:
                    port_matches.append(port)
                    score += 25  # 25 points per matching port
            
            if port_matches:
                evidence['port_matches'][protocol_name] = port_matches
            
            # Check HTTP content patterns
            content_matches = []
            for port, http_data in scan_data['http_responses'].items():
                for endpoint, response in http_data.items():
                    if isinstance(response, dict) and 'content_snippet' in response:
                        content = response['content_snippet'].lower()
                        for pattern in signature['content_patterns']:
                            if pattern.lower() in content:
                                content_matches.append({
                                    'port': port,
                                    'endpoint': endpoint,
                                    'pattern': pattern
                                })
                                score += 30  # 30 points per content match
            
            if content_matches:
                evidence['content_matches'][protocol_name] = content_matches
            
            # Check headers
            header_matches = []
            for port, http_data in scan_data['http_responses'].items():
                for endpoint, response in http_data.items():
                    if isinstance(response, dict) and 'headers' in response:
                        headers = response['headers']
                        for header_pattern in signature.get('headers', []):
                            for header_name, header_value in headers.items():
                                if header_pattern.lower() in header_name.lower() or \
                                   header_pattern.lower() in str(header_value).lower():
                                    header_matches.append({
                                        'port': port,
                                        'endpoint': endpoint,
                                        'header': header_name,
                                        'value': str(header_value)
                                    })
                                    score += 40  # 40 points per header match
            
            if header_matches:
                evidence['header_matches'][protocol_name] = header_matches
            
            # Check TCP banners
            banner_matches = []
            for port, banner in scan_data['tcp_banners'].items():
                for pattern in signature['content_patterns']:
                    if pattern.lower() in banner.lower():
                        banner_matches.append({
                            'port': port,
                            'pattern': pattern,
                            'banner_snippet': banner[:200]
                        })
                        score += 35  # 35 points per banner match
            
            if banner_matches:
                evidence['banner_matches'][protocol_name] = banner_matches
            
            protocol_scores[protocol_name] = score
        
        # Determine best match
        if not protocol_scores or max(protocol_scores.values()) == 0:
            return DiscoveryResult(
                protocol=None,
                confidence=ConfidenceLevel.UNKNOWN.value,
                confidence_score=0.0,
                evidence=evidence,
                scan_data=scan_data
            )
        
        best_protocol = max(protocol_scores, key=protocol_scores.get)
        best_score = protocol_scores[best_protocol]
        
        # Determine confidence level
        if best_score >= 80:
            confidence = ConfidenceLevel.HIGH
        elif best_score >= 40:
            confidence = ConfidenceLevel.MEDIUM
        else:
            confidence = ConfidenceLevel.LOW
        
        # Normalize score to 0-1 range
        confidence_score = min(best_score / 100.0, 1.0)
        
        return DiscoveryResult(
            protocol=best_protocol,
            confidence=confidence.value,
            confidence_score=confidence_score,
            evidence=evidence,
            scan_data=scan_data,
            signature_match={
                'protocol': best_protocol,
                'score': best_score,
                'all_scores': protocol_scores
            }
        )


def discover_node(host: str, node_id: Optional[str] = None, timeout: int = 30, debug: bool = False) -> Dict[str, Any]:
    """
    Convenience function for protocol discovery.
    
    Args:
        host: Target host IP/hostname
        node_id: Optional node identifier
        timeout: Network timeout in seconds
        debug: Enable debug logging
        
    Returns:
        Discovery result as dictionary
    """
    discovery = ProtocolDiscovery(timeout=timeout, debug=debug)
    return discovery.discover_node(host, node_id)
