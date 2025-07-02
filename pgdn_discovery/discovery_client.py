"""
PGDN Discovery Client - Professional DePIN Protocol Discovery

A comprehensive discovery client for identifying DePIN protocols on network nodes
with configurable discovery methods and analysis tools.
"""

import time
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from .discovery_components.probe_scanner import ProbeScanner
from .discovery_components.ai_detector import AIServiceDetector


@dataclass
class DiscoveryResult:
    """Standardized discovery result format"""
    success: bool
    target: str
    discovery_id: str
    timestamp: str
    duration_seconds: float
    enabled_methods: List[str]
    enabled_tools: List[str]
    protocol: Optional[str]
    confidence: float
    evidence: Dict[str, Any]
    raw_data: Dict[str, Any]
    errors: List[str]
    metadata: Dict[str, Any]


class PGDNDiscovery:
    """
    Professional DePIN protocol discovery client
    
    Supports configurable discovery methods and external tools for comprehensive
    protocol identification and network analysis.
    """
    
    AVAILABLE_METHODS = {
        'probe': 'Targeted port/path probing with nmap integration',
        'web': 'HTTP/HTTPS service detection and analysis', 
        'protocol': 'DePIN protocol identification',
        'ai': 'AI-powered protocol detection',
        'signature': 'Binary signature matching'
    }
    
    AVAILABLE_TOOLS = {
        'nmap': 'Network port scanning',
        'http_client': 'HTTP request processing',
        'tls_analyzer': 'TLS/SSL certificate analysis',
        'banner_grabber': 'Service banner detection'
    }
    
    def __init__(self, timeout: int = 30, debug: bool = False):
        """
        Initialize the PGDN Discovery Client
        
        Args:
            timeout: Default timeout for network operations
            debug: Enable debug logging
        """
        self.timeout = timeout
        self.debug = debug
        
        # Initialize discovery components
        self._probe_scanner = ProbeScanner(timeout=timeout)
        self._ai_detector = AIServiceDetector()
        
        # Discovery tracking
        self._discovery_counter = 0
    
    def run_discovery(self, 
                     target: str,
                     enabled_methods: Optional[List[str]] = None,
                     enabled_tools: Optional[List[str]] = None,
                     discovery_config: Optional[Dict[str, Any]] = None) -> DiscoveryResult:
        """
        Run comprehensive protocol discovery on the target
        
        Args:
            target: Target IP address or hostname
            enabled_methods: List of discovery methods to use
            enabled_tools: List of external tools to enable
            discovery_config: Additional configuration options
            
        Returns:
            DiscoveryResult object with protocol identification and evidence
        """
        start_time = time.time()
        self._discovery_counter += 1
        discovery_id = f"discovery_{self._discovery_counter}_{int(time.time())}"
        
        # Default configurations
        if enabled_methods is None:
            enabled_methods = ['probe', 'protocol']
        if enabled_tools is None:
            enabled_tools = ['nmap', 'http_client']
        if discovery_config is None:
            discovery_config = {}
        
        errors = []
        raw_data = {}
        protocol = None
        confidence = 0.0
        evidence = {}
        
        try:
            # Validate configuration
            self._validate_discovery_config(enabled_methods, enabled_tools)
            
            # Run discovery methods
            if 'probe' in enabled_methods:
                raw_data['probe'] = self._run_probe_discovery(target, discovery_config)
            
            if 'web' in enabled_methods:
                raw_data['web'] = self._run_web_discovery(target, discovery_config)
            
            if 'protocol' in enabled_methods:
                protocol_result = self._run_protocol_discovery(target, raw_data, discovery_config)
                protocol = protocol_result.get('protocol')
                confidence = max(confidence, protocol_result.get('confidence', 0.0))
                evidence.update(protocol_result.get('evidence', {}))
                raw_data['protocol'] = protocol_result
            
            if 'ai' in enabled_methods:
                ai_result = self._run_ai_discovery(target, raw_data, discovery_config)
                if ai_result.get('protocol') and ai_result.get('confidence', 0) > confidence:
                    protocol = ai_result.get('protocol')
                    confidence = ai_result.get('confidence', 0.0)
                evidence.update(ai_result.get('evidence', {}))
                raw_data['ai'] = ai_result
            
            success = True
            
        except Exception as e:
            errors.append(f"Discovery failed: {str(e)}")
            success = False
        
        duration_seconds = round(time.time() - start_time, 2)
        
        return DiscoveryResult(
            success=success,
            target=target,
            discovery_id=discovery_id,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
            duration_seconds=duration_seconds,
            enabled_methods=enabled_methods,
            enabled_tools=enabled_tools,
            protocol=protocol,
            confidence=confidence,
            evidence=evidence,
            raw_data=raw_data,
            errors=errors,
            metadata={
                'discovery_version': '1.0.0',
                'target_resolved': target,
                'discovery_config': discovery_config
            }
        )
    
    def run_probe_discovery(self,
                           target: str,
                           probes: List[Dict[str, Any]],
                           include_ai: bool = False) -> DiscoveryResult:
        """
        Run targeted probe discovery (Stage 1 + optional Stage 2 AI)
        
        Args:
            target: Target IP address or hostname
            probes: List of probe configurations [{"port": 9000, "path": "/metrics"}]
            include_ai: Whether to run AI analysis (Stage 2)
            
        Returns:
            DiscoveryResult with probe and optional AI analysis data
        """
        methods = ['probe', 'protocol']
        if include_ai:
            methods.append('ai')
        
        discovery_config = {'probes': probes}
        
        return self.run_discovery(
            target=target,
            enabled_methods=methods,
            enabled_tools=['nmap', 'http_client'],
            discovery_config=discovery_config
        )
    
    def discover_depin_protocols(self,
                                target: str,
                                include_ai: bool = True) -> DiscoveryResult:
        """
        Discover common DePIN protocols using predefined probes
        
        Args:
            target: Target IP address or hostname
            include_ai: Whether to use AI-powered analysis
            
        Returns:
            DiscoveryResult for common DePIN protocols
        """
        # Predefined DePIN protocol probes
        depin_probes = [
            {"port": 9000, "path": "/metrics"},          # Prometheus metrics
            {"port": 8080, "path": "/metrics"},          # Alternative metrics
            {"port": 26657, "path": "/status"},          # Tendermint consensus
            {"port": 1317, "path": "/cosmos/base/tendermint/v1beta1/node_info"},  # Cosmos
            {"port": 9944, "path": "/"},                 # Substrate/Polkadot
            {"port": 8545, "path": "/"},                 # Ethereum JSON-RPC
            {"port": 30303, "path": "/"},                # Ethereum discovery
            {"port": 8000, "path": "/rpc/v0"},           # IPFS/Filecoin
            {"port": 1234, "path": "/rpc/v0"},           # Custom RPC
        ]
        
        return self.run_probe_discovery(
            target=target,
            probes=depin_probes,
            include_ai=include_ai
        )
    
    def get_available_methods(self) -> Dict[str, str]:
        """Get list of available discovery methods"""
        return self.AVAILABLE_METHODS.copy()
    
    def get_available_tools(self) -> Dict[str, str]:
        """Get list of available external tools"""
        return self.AVAILABLE_TOOLS.copy()
    
    def _validate_discovery_config(self, methods: List[str], tools: List[str]) -> None:
        """Validate discovery configuration"""
        # Check method availability
        invalid_methods = [m for m in methods if m not in self.AVAILABLE_METHODS]
        if invalid_methods:
            raise ValueError(f"Invalid discovery methods: {invalid_methods}")
        
        # Check tool availability
        invalid_tools = [t for t in tools if t not in self.AVAILABLE_TOOLS]
        if invalid_tools:
            raise ValueError(f"Invalid tools: {invalid_tools}")
        
        # Check dependencies
        if 'ai' in methods and 'probe' not in methods:
            raise ValueError("AI discovery requires probe method to be enabled")
    
    def _run_probe_discovery(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Run probe-based discovery"""
        probes = config.get('probes', [])
        if not probes:
            # Default probes if none specified
            probes = [
                {"port": 9000, "path": "/metrics"},
                {"port": 8080, "path": "/"},
                {"port": 443, "path": "/"}
            ]
        
        result = self._probe_scanner.probe_services(target, probes)
        return self._probe_scanner.to_dict(result)
    
    def _run_web_discovery(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Run web-based discovery"""
        common_ports = [80, 443, 8080, 8443]
        common_paths = ['/', '/health', '/status', '/api']
        
        web_probes = []
        for port in common_ports:
            for path in common_paths[:2]:  # Limit requests
                web_probes.append({"port": port, "path": path})
        
        result = self._probe_scanner.probe_services(target, web_probes)
        return self._probe_scanner.to_dict(result)
    
    def _run_protocol_discovery(self, target: str, raw_data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Run protocol identification"""
        protocols_detected = []
        confidence_scores = {}
        evidence = {}
        
        # Analyze probe results for protocol indicators
        if 'probe' in raw_data:
            probe_data = raw_data['probe'].get('data', [])
            banner_matches = []
            protocol_signature_matches = []
            
            for probe_result in probe_data:
                # Legacy banner matching
                banners = probe_result.get('matched_banners', [])
                if banners:
                    banner_matches.extend(banners)
                    for banner in banners:
                        if banner not in protocols_detected:
                            protocols_detected.append(banner)
                            confidence_scores[banner] = 0.5  # Lower confidence for banner matches
                
                # New protocol signature matching
                protocol_matches = probe_result.get('protocol_matches', [])
                for match in protocol_matches:
                    protocol = match.get('protocol')
                    confidence = match.get('confidence', 0.0)
                    
                    if protocol and protocol not in protocols_detected:
                        protocols_detected.append(protocol)
                        confidence_scores[protocol] = confidence
                    elif protocol and confidence > confidence_scores.get(protocol, 0.0):
                        # Update with higher confidence
                        confidence_scores[protocol] = confidence
                    
                    protocol_signature_matches.append(match)
            
            evidence['banner_matches'] = banner_matches
            evidence['protocol_signature_matches'] = protocol_signature_matches
        
        # Determine best protocol match
        best_protocol = None
        best_confidence = 0.0
        
        if protocols_detected:
            # Pick the protocol with highest confidence
            for protocol, conf in confidence_scores.items():
                if conf > best_confidence:
                    best_protocol = protocol
                    best_confidence = conf
        
        return {
            'protocol': best_protocol,
            'confidence': best_confidence,
            'detected_protocols': protocols_detected,
            'confidence_scores': confidence_scores,
            'evidence': evidence,
            'analysis_method': 'signature_and_banner'
        }
    
    def _run_ai_discovery(self, target: str, raw_data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Run AI-powered discovery"""
        # Convert raw data to format expected by AI detector
        scan_data = {
            'nmap': {},
            'probes': {}
        }
        
        # Convert probe results
        if 'probe' in raw_data:
            probe_data = raw_data['probe'].get('data', [])
            ports = []
            
            for probe_result in probe_data:
                if probe_result.get('status_code', 0) > 0:
                    port = probe_result.get('port')
                    ports.append(port)
                    path = probe_result.get('path', '/')
                    probe_key = f"{port}_{path.replace('/', '_')}"
                    scan_data['probes'][probe_key] = {
                        'status': probe_result.get('status_code'),
                        'url': f"http://{target}:{port}{path}",
                        'headers': probe_result.get('headers', {}),
                        'body': probe_result.get('body', ''),
                        'response_time_ms': 100
                    }
            
            scan_data['nmap'] = {'ports': ports, 'services': {}}
        
        try:
            protocol, confidence, evidence = self._ai_detector.analyze_service_with_ai(target, scan_data, 1)
            return {
                'protocol': protocol,
                'confidence': confidence,
                'evidence': evidence,
                'analysis_method': 'ai_powered'
            }
        except Exception as e:
            return {
                'protocol': None,
                'confidence': 0.0,
                'evidence': {'error': str(e)},
                'analysis_method': 'ai_powered'
            }


# Convenience functions for easy usage
def create_discovery_client(**kwargs) -> PGDNDiscovery:
    """Create a PGDN Discovery Client instance"""
    return PGDNDiscovery(**kwargs)


def discover_node(target: str, **kwargs) -> DiscoveryResult:
    """Quick discovery with default settings"""
    client = PGDNDiscovery()
    return client.run_discovery(target, **kwargs) 