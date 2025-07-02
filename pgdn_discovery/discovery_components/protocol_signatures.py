"""
Protocol Signature Matcher - Advanced protocol detection using signatures

This module provides sophisticated protocol detection using regex patterns,
response analysis, and protocol-specific indicators to differentiate between
similar protocols like Sui and Walrus that may share ports.
"""

import re
import json
import yaml
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ProtocolSignature:
    """Protocol signature configuration"""
    protocol: str
    signatures: List[Dict[str, Any]]
    ports: List[int]
    paths: List[str]
    confidence_boost: float = 0.0


@dataclass
class SignatureMatch:
    """Result of signature matching"""
    protocol: str
    confidence: float
    signature_name: str
    matched_content: str
    evidence: Dict[str, Any]


class ProtocolSignatureMatcher:
    """Advanced protocol signature matching system"""
    
    def __init__(self):
        self.protocol_signatures = self._load_protocol_signatures()
    
    def _load_protocol_signatures(self) -> Dict[str, ProtocolSignature]:
        """Load protocol signature definitions from YAML files"""
        signatures = {}
        
        # Get the path to the signatures directory
        current_dir = Path(__file__).parent.parent  # Go up from discovery_components to pgdn_discovery
        signatures_dir = current_dir / "signatures"
        
        if not signatures_dir.exists():
            raise FileNotFoundError(f"Signatures directory not found: {signatures_dir}")
        
        # Load all YAML files in the signatures directory
        for yaml_file in signatures_dir.glob("*.yaml"):
            try:
                protocol_name = yaml_file.stem  # filename without extension
                signature_config = self._load_signature_from_yaml(yaml_file)
                signatures[protocol_name] = signature_config
            except Exception as e:
                print(f"Warning: Failed to load signature file {yaml_file}: {e}")
                continue
        
        return signatures
    
    def _load_signature_from_yaml(self, yaml_file: Path) -> ProtocolSignature:
        """Load a single protocol signature from YAML file"""
        with open(yaml_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        protocol_name = yaml_file.stem
        name = data.get('name', protocol_name)
        network_type = data.get('network_type', 'unknown')
        default_ports = data.get('default_ports', [])
        
        # Convert YAML signatures to our internal format
        signatures = []
        for sig_data in data.get('signatures', []):
            signature = {
                'name': sig_data.get('label', 'unknown'),
                'regex': sig_data.get('regex', ''),
                'confidence': self._calculate_confidence_from_signature(sig_data),
                'type': self._infer_signature_type(sig_data),
                'version_group': sig_data.get('version_group', '')
            }
            
            # Add path requirements if we can infer them
            path_required = self._infer_path_requirement(sig_data, data.get('probes', []))
            if path_required:
                signature['path_required'] = path_required
            
            signatures.append(signature)
        
        # Extract paths from probes
        paths = ['/']  # Default path
        for probe in data.get('probes', []):
            payload = probe.get('payload', '')
            # Extract path from HTTP request payload
            if 'GET ' in payload or 'POST ' in payload:
                lines = payload.split('\\r\\n')
                if lines:
                    request_line = lines[0]
                    parts = request_line.split(' ')
                    if len(parts) >= 2:
                        path = parts[1]
                        if path not in paths:
                            paths.append(path)
        
        return ProtocolSignature(
            protocol=protocol_name,
            signatures=signatures,
            ports=default_ports,
            paths=paths
        )
    
    def _calculate_confidence_from_signature(self, sig_data: Dict[str, Any]) -> float:
        """Calculate confidence score based on signature characteristics"""
        regex = sig_data.get('regex', '')
        label = sig_data.get('label', '').lower()
        
        # Higher confidence for more specific patterns
        if 'version=' in regex or 'version"' in regex:
            return 0.95
        elif 'rpc' in label or 'api' in label:
            return 0.9
        elif 'node' in label or 'validator' in label:
            return 0.85
        elif 'metrics' in label:
            return 0.8
        else:
            return 0.7
    
    def _infer_signature_type(self, sig_data: Dict[str, Any]) -> str:
        """Infer signature type from label and regex"""
        label = sig_data.get('label', '').lower()
        regex = sig_data.get('regex', '').lower()
        
        if 'metrics' in label or 'help' in regex or 'type' in regex:
            return 'metrics'
        elif 'rpc' in label or 'jsonrpc' in regex:
            return 'rpc_response'
        elif 'api' in label or 'version' in label:
            return 'api_response'
        elif 'header' in label or 'x-' in regex:
            return 'header'
        elif 'health' in label:
            return 'health_check'
        else:
            return 'banner'
    
    def _infer_path_requirement(self, sig_data: Dict[str, Any], probes: List[Dict[str, Any]]) -> Optional[str]:
        """Infer path requirement from signature and probes"""
        label = sig_data.get('label', '').lower()
        
        # Look for specific path hints in the label
        if 'metrics' in label:
            # Find metrics probe
            for probe in probes:
                if 'metrics' in probe.get('name', '').lower():
                    payload = probe.get('payload', '')
                    if 'GET /metrics' in payload:
                        return '/metrics'
                    elif 'GET /debug/metrics' in payload:
                        return '/debug/metrics'
        elif 'health' in label:
            return '/health'
        elif 'status' in label:
            return '/status'
        
        return None
    
    def match_protocol_signatures(self, probe_results: List[Dict[str, Any]]) -> List[SignatureMatch]:
        """
        Match protocol signatures against probe results
        
        Args:
            probe_results: List of probe result dictionaries
            
        Returns:
            List of signature matches with confidence scores
        """
        matches = []
        
        for probe_result in probe_results:
            if probe_result.get('error') or probe_result.get('status_code', 0) < 200:
                continue
                
            port = probe_result.get('port')
            path = probe_result.get('path', '/')
            headers = probe_result.get('headers', {})
            body = probe_result.get('body', '')
            
            # Check each protocol's signatures
            for protocol_name, protocol_sig in self.protocol_signatures.items():
                # Skip if port doesn't match protocol's expected ports
                if port and port not in protocol_sig.ports:
                    continue
                
                protocol_matches = self._check_protocol_signatures(
                    protocol_sig, port, path, headers, body
                )
                matches.extend(protocol_matches)
        
        return self._deduplicate_and_score_matches(matches)
    
    def _check_protocol_signatures(self, 
                                  protocol_sig: ProtocolSignature,
                                  port: int, 
                                  path: str, 
                                  headers: Dict[str, str], 
                                  body: str) -> List[SignatureMatch]:
        """Check signatures for a specific protocol"""
        matches = []
        
        for signature in protocol_sig.signatures:
            match_result = self._check_single_signature(
                signature, protocol_sig.protocol, port, path, headers, body
            )
            if match_result:
                matches.append(match_result)
        
        return matches
    
    def _check_single_signature(self, 
                               signature: Dict[str, Any],
                               protocol: str,
                               port: int,
                               path: str, 
                               headers: Dict[str, str], 
                               body: str) -> Optional[SignatureMatch]:
        """Check a single signature pattern"""
        regex_pattern = signature['regex']
        signature_type = signature.get('type', 'unknown')
        confidence = signature.get('confidence', 0.5)
        path_required = signature.get('path_required')
        
        # Check path requirement
        if path_required and path != path_required:
            return None
        
        # Prepare content to search based on signature type
        search_content = ""
        content_source = ""
        
        if signature_type == 'header':
            # Search in headers
            header_content = ' '.join([f"{k}: {v}" for k, v in headers.items()])
            search_content = header_content.lower()
            content_source = "headers"
        elif signature_type in ['metrics', 'api_response', 'rpc_response', 'banner', 'health_check', 'endpoint', 'api_endpoint']:
            # Search in body
            search_content = body
            content_source = "body"
        else:
            # Search in both
            header_content = ' '.join([f"{k}: {v}" for k, v in headers.items()])
            search_content = f"{header_content} {body}"
            content_source = "headers_and_body"
        
        # Apply regex matching
        try:
            match = re.search(regex_pattern, search_content, re.IGNORECASE | re.MULTILINE)
            if match:
                matched_content = match.group(0)
                version = match.groupdict().get('version', '')
                
                evidence = {
                    'signature_type': signature_type,
                    'content_source': content_source,
                    'port': port,
                    'path': path,
                    'version': version,
                    'regex_pattern': regex_pattern,
                    'match_length': len(matched_content)
                }
                
                return SignatureMatch(
                    protocol=protocol,
                    confidence=confidence,
                    signature_name=signature['name'],
                    matched_content=matched_content[:200],  # Limit content length
                    evidence=evidence
                )
        except re.error:
            # Invalid regex pattern
            pass
        
        return None
    
    def _deduplicate_and_score_matches(self, matches: List[SignatureMatch]) -> List[SignatureMatch]:
        """Deduplicate matches and calculate final scores"""
        if not matches:
            return []
        
        # Group matches by protocol
        protocol_matches = {}
        for match in matches:
            if match.protocol not in protocol_matches:
                protocol_matches[match.protocol] = []
            protocol_matches[match.protocol].append(match)
        
        # Calculate best match per protocol
        final_matches = []
        for protocol, prot_matches in protocol_matches.items():
            # Sort by confidence (highest first)
            prot_matches.sort(key=lambda x: x.confidence, reverse=True)
            
            # Take the best match but boost confidence if multiple matches
            best_match = prot_matches[0]
            if len(prot_matches) > 1:
                # Boost confidence for multiple matching signatures
                confidence_boost = min(0.1 * (len(prot_matches) - 1), 0.3)
                best_match.confidence = min(best_match.confidence + confidence_boost, 1.0)
                best_match.evidence['multiple_signatures'] = len(prot_matches)
                best_match.evidence['all_signatures'] = [m.signature_name for m in prot_matches]
            
            final_matches.append(best_match)
        
        # Sort final matches by confidence
        final_matches.sort(key=lambda x: x.confidence, reverse=True)
        return final_matches
    
    def get_protocol_info(self, protocol: str) -> Optional[ProtocolSignature]:
        """Get protocol signature information"""
        return self.protocol_signatures.get(protocol)
    
    def add_custom_protocol(self, protocol_signature: ProtocolSignature) -> None:
        """Add a custom protocol signature"""
        self.protocol_signatures[protocol_signature.protocol] = protocol_signature
