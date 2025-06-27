#!/usr/bin/env python3
"""
Basic tests for PGDN Discovery functionality
"""

import unittest
from unittest.mock import patch, MagicMock
from pgdn_discovery.discovery import NetworkProber, discover_node, COMMON_PORTS, COMMON_ENDPOINTS


class TestNetworkProber(unittest.TestCase):
    """Test the NetworkProber class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.prober = NetworkProber(timeout=1)
    
    def test_init(self):
        """Test initialization"""
        self.assertEqual(self.prober.timeout, 1)
    
    @patch('socket.socket')
    def test_port_scan_open_port(self, mock_socket):
        """Test port scan with an open port"""
        # Mock successful connection
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket.return_value = mock_sock
        
        result = self.prober._port_scan("127.0.0.1", [80])
        self.assertEqual(result, [80])
        mock_sock.close.assert_called_once()
    
    @patch('socket.socket')
    def test_port_scan_closed_port(self, mock_socket):
        """Test port scan with a closed port"""
        # Mock failed connection
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1
        mock_socket.return_value = mock_sock
        
        result = self.prober._port_scan("127.0.0.1", [80])
        self.assertEqual(result, [])
        mock_sock.close.assert_called_once()
    
    @patch('socket.socket')
    def test_port_scan_exception(self, mock_socket):
        """Test port scan with exception"""
        # Mock exception during connection
        mock_socket.side_effect = Exception("Network error")
        
        result = self.prober._port_scan("127.0.0.1", [80])
        self.assertEqual(result, [])
    
    def test_discover_stage_1(self):
        """Test discovery stage 1 (port scan)"""
        with patch.object(self.prober, '_port_scan', return_value=[80, 443]):
            with patch.object(self.prober, '_get_tls_info', return_value={}):
                result = self.prober.discover("127.0.0.1", stage="1")
                
                self.assertEqual(result.ip, "127.0.0.1")
                self.assertEqual(result.open_ports, [80, 443])
                self.assertEqual(result.http_responses, {})
                self.assertIsInstance(result.duration_seconds, float)
    
    def test_discover_stage_2(self):
        """Test discovery stage 2 (web scan)"""
        with patch.object(self.prober, '_web_scan', return_value={80: {"/": {"status_code": 200}}}):
            result = self.prober.discover("127.0.0.1", stage="2", ports=[80])
            
            self.assertEqual(result.ip, "127.0.0.1")
            self.assertEqual(result.open_ports, [80])  # Should assume ports are open for stage 2
            self.assertEqual(result.http_responses, {80: {"/": {"status_code": 200}}})
    
    def test_discover_all_stages(self):
        """Test discovery with all stages"""
        with patch.object(self.prober, '_port_scan', return_value=[80]):
            with patch.object(self.prober, '_get_tls_info', return_value={}):
                with patch.object(self.prober, '_web_scan', return_value={80: {"/": {"status_code": 200}}}):
                    result = self.prober.discover("127.0.0.1", stage="all")
                    
                    self.assertEqual(result.ip, "127.0.0.1")
                    self.assertEqual(result.open_ports, [80])
                    self.assertEqual(result.http_responses, {80: {"/": {"status_code": 200}}})
    
    def test_discover_with_defaults(self):
        """Test discovery uses default ports and paths"""
        with patch.object(self.prober, '_port_scan') as mock_port_scan:
            with patch.object(self.prober, '_get_tls_info'):
                with patch.object(self.prober, '_web_scan') as mock_web_scan:
                    mock_port_scan.return_value = []
                    mock_web_scan.return_value = {}
                    
                    self.prober.discover("127.0.0.1")
                    
                    # Check that defaults were used
                    mock_port_scan.assert_called_with("127.0.0.1", COMMON_PORTS)
                    mock_web_scan.assert_called_with("127.0.0.1", [], COMMON_ENDPOINTS)


class TestConvenienceFunction(unittest.TestCase):
    """Test the discover_node convenience function"""
    
    @patch('pgdn_discovery.discovery.NetworkProber')
    def test_discover_node(self, mock_prober_class):
        """Test the discover_node convenience function"""
        # Mock the prober instance and its discover method
        mock_prober = MagicMock()
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {"ip": "127.0.0.1", "open_ports": [80]}
        mock_prober.discover.return_value = mock_result
        mock_prober_class.return_value = mock_prober
        
        result = discover_node("127.0.0.1", stage="1", ports=[80], timeout=10)
        
        # Verify prober was initialized with correct timeout
        mock_prober_class.assert_called_once_with(timeout=10)
        
        # Verify discover was called with correct arguments
        mock_prober.discover.assert_called_once_with("127.0.0.1", "1", [80], None)
        
        # Verify result was converted to dict
        self.assertEqual(result, {"ip": "127.0.0.1", "open_ports": [80]})


class TestConstants(unittest.TestCase):
    """Test the default constants"""
    
    def test_common_ports(self):
        """Test that COMMON_PORTS contains expected ports"""
        expected_ports = [80, 443, 8080, 9000, 8545, 30303]
        self.assertEqual(COMMON_PORTS, expected_ports)
    
    def test_common_endpoints(self):
        """Test that COMMON_ENDPOINTS contains expected paths"""
        expected_paths = ["/", "/metrics", "/health", "/rpc/v0", "/status"]
        self.assertEqual(COMMON_ENDPOINTS, expected_paths)


if __name__ == "__main__":
    # Run the tests
    unittest.main(verbosity=2) 