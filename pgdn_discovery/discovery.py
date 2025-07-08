"""
PGDN Discovery - Modular Staged Probing Pipeline

A clean, modular library for network probing with staged discovery.
Supports both programmatic and CLI usage.
"""

import time
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

# Configure logger for this module
logger = logging.getLogger(__name__)

def _load_signatures():
    """
    Load signatures from the signatures.yaml file.
    Tries multiple methods to find the file for both installed and development scenarios.
    """
    logger.info("Loading protocol signatures...")
    
    try:
        import yaml
        from pathlib import Path
    except ImportError:
        logger.error("CRITICAL: yaml library not available - cannot load protocol signatures")
        return None
        
    # Method 1: Try modern importlib.resources first (for installed packages)
    try:
        from importlib import resources
        signatures_content = resources.files('pgdn_discovery').joinpath('signatures.yaml').read_text(encoding='utf-8')
        logger.info("Successfully loaded signatures from installed package using importlib.resources")
        signatures_data = yaml.safe_load(signatures_content)
        protocol_count = len(signatures_data.get('protocols', {}))
        logger.info(f"Loaded {protocol_count} protocol signatures: {list(signatures_data.get('protocols', {}).keys())}")
        return signatures_data
    except (ImportError, FileNotFoundError, AttributeError, Exception) as e:
        logger.debug(f"importlib.resources failed: {e}")
    
    # Method 2: Try legacy pkg_resources as fallback (for older installations)
    try:
        import pkg_resources
        signatures_content = pkg_resources.resource_string('pgdn_discovery', 'signatures.yaml').decode('utf-8')
        logger.info("Successfully loaded signatures from installed package using pkg_resources")
        signatures_data = yaml.safe_load(signatures_content)
        protocol_count = len(signatures_data.get('protocols', {}))
        logger.info(f"Loaded {protocol_count} protocol signatures: {list(signatures_data.get('protocols', {}).keys())}")
        return signatures_data
    except (ImportError, FileNotFoundError, ModuleNotFoundError, Exception) as e:
        logger.debug(f"pkg_resources failed: {e}")
    
    # Method 3: Final fallback to file path method (for development)
    current_dir = Path(__file__).parent
    signatures_file = current_dir / "signatures.yaml"
    
    if not signatures_file.exists():
        logger.error(f"CRITICAL: Signatures file not found at {signatures_file}")
        logger.error("This means protocol discovery will not work. Please check your installation.")
        return None
    
    logger.info(f"Loading signatures from development path: {signatures_file}")
    try:
        with open(signatures_file, 'r', encoding='utf-8') as f:
            signatures_data = yaml.safe_load(f)
            protocol_count = len(signatures_data.get('protocols', {}))
            logger.info(f"Loaded {protocol_count} protocol signatures: {list(signatures_data.get('protocols', {}).keys())}")
            return signatures_data
    except Exception as e:
        logger.error(f"CRITICAL: Error loading signatures from file: {e}")
        return None

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
        
        logger.info(f"Starting protocol discovery for {ip}")
        if protocol_filter:
            logger.info(f"Using protocol filter: {protocol_filter}")
        
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
            logger.debug(f"Starting RPC protocol discovery for {ip}")
            rpc_results = self._discover_rpc_protocol(ip, protocol_filter)
            logger.debug(f"RPC discovery found {len(rpc_results)} protocols")
            
            logger.debug(f"Starting HTTP protocol discovery for {ip}")
            http_results = self._discover_http_protocol(ip, protocol_filter)
            logger.debug(f"HTTP discovery found {len(http_results)} protocols")
            
            # Combine results from both discovery methods
            all_results = rpc_results + http_results
            logger.info(f"Total protocols discovered: {len(all_results)}")
            
            if all_results:
                for protocol_result in all_results:
                    endpoint = protocol_result["endpoint"]
                    port = int(endpoint.split(':')[-1]) if ':' in endpoint else (443 if 'https' in endpoint else 80)
                    
                    logger.debug(f"Processing protocol {protocol_result['protocol']} on port {port}")
                    
                    if port not in result.open_ports:
                        result.open_ports.append(port)
                    
                    if port not in result.http_responses:
                        result.http_responses[port] = {}
                    
                    result.http_responses[port]["/"] = {
                        "status_code": 200,
                        "protocol": protocol_result["protocol"],
                        "endpoint": endpoint
                    }
            else:
                logger.info(f"No protocols discovered for {ip}")
        
        except Exception as e:
            logger.error(f"Discovery error for {ip}: {str(e)}")
            result.errors["discovery"] = str(e)
        
        result.duration_seconds = round(time.time() - start_time, 2)
        logger.info(f"Discovery completed for {ip} in {result.duration_seconds}s")
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
            logger.warning("requests library not available, skipping RPC discovery")
            return found_protocols
        
        try:
            signatures_data = _load_signatures()
            if signatures_data is None:
                logger.error("CRITICAL: Could not load signatures file, RPC discovery will not work")
                return found_protocols
            
            protocols = signatures_data.get('protocols', {})
            
            # Validate protocol filter if provided
            if protocol_filter:
                if protocol_filter not in protocols:
                    logger.error(f"Protocol filter '{protocol_filter}' not found in signatures")
                    logger.info(f"Available protocols: {list(protocols.keys())}")
                    return found_protocols
                # Only scan the specified protocol
                protocols_to_scan = {protocol_filter: protocols[protocol_filter]}
                logger.info(f"RPC scan filtered to protocol: {protocol_filter}")
            else:
                # Scan all protocols
                protocols_to_scan = protocols
                logger.info(f"RPC scan will test all {len(protocols_to_scan)} protocols")
            
            for protocol_name, config in protocols_to_scan.items():
                # Only process protocols with rpc_method (RPC-based)
                if 'rpc_method' not in config:
                    logger.debug(f"Skipping {protocol_name} - no rpc_method defined")
                    continue
                
                rpc_method = config.get('rpc_method')
                ports = config.get('ports', [])
                logger.info(f"Starting RPC scan for {protocol_name} protocol using method '{rpc_method}' on ports {ports}")
                    
                for port in ports:
                    try:
                        https_ports = [443, 8443, 9443]
                        protocol = "https" if port in https_ports else "http"
                        url = f"{protocol}://{ip}:{port}"
                        
                        logger.info(f"Testing RPC endpoint: {url} with method '{rpc_method}'")
                        
                        response = requests.post(url, json={
                            "jsonrpc": "2.0",
                            "method": rpc_method,
                            "params": [],
                            "id": 1
                        }, timeout=self.timeout, verify=False)
                        
                        if response.status_code == 200:
                            try:
                                json_response = response.json()
                                if "result" in json_response:
                                    logger.info(f"SUCCESS: Discovered {protocol_name} protocol at {url}")
                                    found_protocols.append({
                                        "protocol": protocol_name,
                                        "endpoint": url
                                    })
                                    # Exit early if we've found 3 protocols (max supported)
                                    if len(found_protocols) >= 3:
                                        logger.info("Maximum protocols found, exiting early")
                                        return found_protocols
                                    break  # Found this protocol, try next protocol
                                else:
                                    logger.info(f"RPC call to {url} returned response without result field")
                            except Exception as e:
                                logger.warning(f"Failed to parse JSON response from {url}: {str(e)}")
                                continue
                        else:
                            logger.info(f"RPC call to {url} returned status {response.status_code}")
                                
                    except Exception as e:
                        logger.info(f"RPC call to {url} failed: {str(e)}")
                        continue
                        
        except Exception as e:
            logger.error(f"Error in RPC protocol discovery: {str(e)}")
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
            logger.warning("requests library not available, skipping HTTP discovery")
            return found_protocols
        
        try:
            signatures_data = _load_signatures()
            if signatures_data is None:
                logger.error("CRITICAL: Could not load signatures file, HTTP discovery will not work")
                return found_protocols
            
            protocols = signatures_data.get('protocols', {})
            
            # Validate protocol filter if provided
            if protocol_filter:
                if protocol_filter not in protocols:
                    logger.error(f"Protocol filter '{protocol_filter}' not found in signatures")
                    logger.info(f"Available protocols: {list(protocols.keys())}")
                    return found_protocols
                # Only scan the specified protocol
                protocols_to_scan = {protocol_filter: protocols[protocol_filter]}
                logger.info(f"HTTP scan filtered to protocol: {protocol_filter}")
            else:
                # Scan all protocols
                protocols_to_scan = protocols
                logger.info(f"HTTP scan will test all {len(protocols_to_scan)} protocols")
            
            for protocol_name, config in protocols_to_scan.items():
                # Only process protocols with api_method (HTTP-based)
                if 'api_method' not in config:
                    logger.debug(f"Skipping {protocol_name} - no api_method defined")
                    continue
                
                api_method = config.get('api_method')
                ports = config.get('ports', [])
                logger.info(f"Starting HTTP scan for {protocol_name} protocol using method '{api_method}' on ports {ports}")
                    
                for port in ports:
                    logger.info(f"Testing HTTP endpoint: {ip}:{port} with method '{api_method}'")
                    
                    if self._probe_http_node(ip, port, api_method, self.timeout):
                        https_ports = [443, 8443, 9443]
                        protocol = "https" if port in https_ports else "http"
                        url = f"{protocol}://{ip}:{port}"
                        
                        logger.info(f"SUCCESS: Discovered {protocol_name} protocol at {url}")
                        found_protocols.append({
                            "protocol": protocol_name,
                            "endpoint": url
                        })
                        
                        # Exit early if we've found 3 protocols (max supported)
                        if len(found_protocols) >= 3:
                            logger.info("Maximum protocols found, exiting early")
                            return found_protocols
                        break  # Found this protocol, try next protocol
                        
        except Exception as e:
            logger.error(f"Error in HTTP protocol discovery: {str(e)}")
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
        
        logger.info(f"Probing HTTP node at {url}")
        
        try:
            response = requests.get(url, timeout=timeout, verify=False)
            logger.info(f"HTTP probe to {url} returned status {response.status_code}")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    # For Walrus, check for 'validators' key
                    if api_method == "getValidators" and "validators" in data:
                        logger.info(f"HTTP probe to {url} successful - found validators key")
                        return True
                    # For other API methods, just check if we get valid JSON
                    elif api_method != "getValidators" and data:
                        logger.info(f"HTTP probe to {url} successful - got valid JSON response")
                        return True
                    else:
                        logger.info(f"HTTP probe to {url} returned JSON but missing expected keys")
                except Exception as e:
                    logger.info(f"HTTP probe to {url} failed to parse JSON: {str(e)}")
                    pass
            else:
                logger.info(f"HTTP probe to {url} failed with status {response.status_code}")
        except Exception as e:
            logger.info(f"HTTP probe to {url} failed: {str(e)}")
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
    logger.debug(f"discover_node called for {ip} with timeout={timeout}, filter={protocol_filter}")
    discoverer = ProtocolDiscoverer(timeout=timeout)
    result = discoverer.discover(ip, protocol_filter=protocol_filter)
    logger.debug(f"discover_node returning result with {len(result.open_ports)} open ports")
    return result.to_dict()


if __name__ == "__main__":
    # Simple test
    result = discover_node("127.0.0.1", timeout=5)
    print(result)
