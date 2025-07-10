"""
Unit tests for network scanner
"""

import pytest
import socket
import time
from unittest.mock import Mock, patch, MagicMock
from unittest import TestCase

from netscan.scanner.network import NetworkScanner
from netscan.utils.error_handling import NetworkError, ConnectionTimeoutError
from tests import TEST_SCAN_RESULTS


class TestNetworkScanner:
    """Test cases for NetworkScanner"""
    
    def setup_method(self):
        """Setup test scanner for each test"""
        self.scanner = NetworkScanner(timeout=2, threads=5)
    
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        assert self.scanner.timeout == 2
        assert self.scanner.threads == 5
        assert self.scanner.nm is not None
    
    def test_validate_ip_range_valid_cidr(self):
        """Test IP range validation with valid CIDR"""
        valid_ranges = [
            '192.168.1.0/24',
            '10.0.0.0/8',
            '172.16.0.0/12',
            '127.0.0.1/32'
        ]
        
        for ip_range in valid_ranges:
            assert self.scanner.validate_ip_range(ip_range) is True
    
    def test_validate_ip_range_invalid(self):
        """Test IP range validation with invalid ranges"""
        invalid_ranges = [
            '192.168.1.0/33',  # Invalid CIDR
            '300.168.1.0/24',  # Invalid IP
            'invalid-range',   # Non-IP string
            '192.168.1.0-192.168.1.10'  # Range format not supported
        ]
        
        for ip_range in invalid_ranges:
            assert self.scanner.validate_ip_range(ip_range) is False
    
    def test_expand_ip_range_single_ip(self):
        """Test expanding single IP address"""
        ip_range = '192.168.1.100'
        expanded = self.scanner.expand_ip_range(ip_range)
        
        assert len(expanded) == 1
        assert expanded[0] == '192.168.1.100'
    
    def test_expand_ip_range_small_cidr(self):
        """Test expanding small CIDR block"""
        ip_range = '192.168.1.0/30'  # 4 addresses, 2 hosts
        expanded = self.scanner.expand_ip_range(ip_range)
        
        assert len(expanded) == 2
        assert '192.168.1.1' in expanded
        assert '192.168.1.2' in expanded
    
    def test_expand_ip_range_invalid(self):
        """Test expanding invalid IP range"""
        ip_range = 'invalid-range'
        expanded = self.scanner.expand_ip_range(ip_range)
        
        assert len(expanded) == 0
    
    @patch('socket.socket')
    def test_check_ssh_port_success(self, mock_socket):
        """Test successful SSH port check"""
        # Mock socket behavior for successful connection
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 0  # Success
        mock_sock.recv.return_value = b'SSH-2.0-OpenSSH_8.0'
        mock_socket.return_value = mock_sock
        
        # Mock hostname resolution
        with patch('socket.gethostbyaddr') as mock_gethostbyaddr:
            mock_gethostbyaddr.return_value = ('test-host', [], ['192.168.1.100'])
            
            result = self.scanner.check_ssh_port('192.168.1.100', 22)
            
            assert result['ip_address'] == '192.168.1.100'
            assert result['ssh_port'] == 22
            assert result['status'] == 'active'
            assert result['hostname'] == 'test-host'
            assert result['ssh_banner'] == 'SSH-2.0-OpenSSH_8.0'
            assert result['response_time'] is not None
    
    @patch('socket.socket')
    def test_check_ssh_port_connection_refused(self, mock_socket):
        """Test SSH port check with connection refused"""
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 111  # Connection refused
        mock_socket.return_value = mock_sock
        
        result = self.scanner.check_ssh_port('192.168.1.100', 22)
        
        assert result['ip_address'] == '192.168.1.100'
        assert result['ssh_port'] == 22
        assert result['status'] == 'inactive'
        assert result['hostname'] is None
        assert result['response_time'] is not None
    
    @patch('socket.socket')
    def test_check_ssh_port_timeout(self, mock_socket):
        """Test SSH port check with timeout"""
        mock_sock = Mock()
        mock_sock.connect_ex.side_effect = socket.timeout()
        mock_socket.return_value = mock_sock
        
        # The enhanced error handling should catch this
        result = self.scanner.check_ssh_port('192.168.1.100', 22)
        
        assert result['ip_address'] == '192.168.1.100'
        assert result['ssh_port'] == 22
        assert result['status'] == 'timeout'
        assert 'timeout' in result['error'].lower()
        assert result['response_time'] is not None
    
    @patch('socket.socket')
    def test_check_ssh_port_hostname_resolution_failure(self, mock_socket):
        """Test SSH port check with hostname resolution failure"""
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 0  # Success
        mock_sock.recv.return_value = b'SSH-2.0-OpenSSH_8.0'
        mock_socket.return_value = mock_sock
        
        # Mock hostname resolution failure
        with patch('socket.gethostbyaddr') as mock_gethostbyaddr:
            mock_gethostbyaddr.side_effect = socket.herror("No hostname")
            
            result = self.scanner.check_ssh_port('192.168.1.100', 22)
            
            assert result['status'] == 'active'
            assert result['hostname'] is None  # Should be None when resolution fails
    
    @patch('socket.socket')
    def test_check_ssh_port_banner_retrieval_failure(self, mock_socket):
        """Test SSH port check with banner retrieval failure"""
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 0  # Success
        mock_sock.recv.side_effect = socket.timeout()  # Banner retrieval fails
        mock_socket.return_value = mock_sock
        
        result = self.scanner.check_ssh_port('192.168.1.100', 22)
        
        assert result['status'] == 'active'
        assert result['ssh_banner'] is None  # Should be None when banner fails
    
    @patch('netscan.scanner.network.NetworkScanner.check_ssh_port')
    def test_concurrent_scan_success(self, mock_check_ssh_port):
        """Test successful concurrent scan"""
        # Mock successful scan results
        mock_check_ssh_port.side_effect = [
            {
                'ip_address': '192.168.1.100',
                'ssh_port': 22,
                'status': 'active',
                'hostname': 'host1',
                'response_time': 0.5
            },
            {
                'ip_address': '192.168.1.101',
                'ssh_port': 22,
                'status': 'inactive',
                'hostname': None,
                'response_time': 1.0
            }
        ]
        
        ip_list = ['192.168.1.100', '192.168.1.101']
        results = self.scanner.concurrent_scan(ip_list, 22)
        
        assert len(results) == 2
        assert results[0]['status'] == 'active'
        assert results[1]['status'] == 'inactive'
        assert mock_check_ssh_port.call_count == 2
    
    @patch('netscan.scanner.network.NetworkScanner.check_ssh_port')
    def test_concurrent_scan_with_exceptions(self, mock_check_ssh_port):
        """Test concurrent scan with exceptions"""
        # Mock one successful result and one exception
        mock_check_ssh_port.side_effect = [
            {
                'ip_address': '192.168.1.100',
                'ssh_port': 22,
                'status': 'active',
                'hostname': 'host1',
                'response_time': 0.5
            },
            Exception("Network error")
        ]
        
        ip_list = ['192.168.1.100', '192.168.1.101']
        results = self.scanner.concurrent_scan(ip_list, 22)
        
        assert len(results) == 2
        assert results[0]['status'] == 'active'
        # The second result should be an error result
        error_result = next((r for r in results if r['status'] == 'error'), None)
        assert error_result is not None
        assert 'Network error' in error_result['error']
    
    @patch('netscan.scanner.network.NetworkScanner.nmap_scan')
    @patch('netscan.scanner.network.NetworkScanner.concurrent_scan')
    def test_scan_range_with_nmap_success(self, mock_concurrent_scan, mock_nmap_scan):
        """Test scan_range with successful nmap scan"""
        # Mock successful nmap scan
        mock_nmap_scan.return_value = [
            {
                'ip_address': '192.168.1.100',
                'hostname': 'host1',
                'status': 'active',
                'ssh_port': 22
            }
        ]
        
        results = self.scanner.scan_range('192.168.1.0/30', 22, use_nmap=True)
        
        assert len(results) == 1
        assert results[0]['status'] == 'active'
        mock_nmap_scan.assert_called_once()
        mock_concurrent_scan.assert_not_called()
    
    @patch('netscan.scanner.network.NetworkScanner.nmap_scan')
    @patch('netscan.scanner.network.NetworkScanner.concurrent_scan')
    def test_scan_range_nmap_fallback_to_socket(self, mock_concurrent_scan, mock_nmap_scan):
        """Test scan_range fallback to socket scan when nmap fails"""
        # Mock nmap scan failure
        mock_nmap_scan.return_value = []
        
        # Mock successful concurrent scan
        mock_concurrent_scan.return_value = [
            {
                'ip_address': '192.168.1.1',
                'hostname': None,
                'status': 'active',
                'ssh_port': 22
            }
        ]
        
        results = self.scanner.scan_range('192.168.1.0/30', 22, use_nmap=True)
        
        assert len(results) == 1
        assert results[0]['status'] == 'active'
        mock_nmap_scan.assert_called_once()
        mock_concurrent_scan.assert_called_once()
    
    @patch('netscan.scanner.network.NetworkScanner.concurrent_scan')
    def test_scan_range_socket_only(self, mock_concurrent_scan):
        """Test scan_range with socket scan only"""
        # Mock successful concurrent scan
        mock_concurrent_scan.return_value = [
            {
                'ip_address': '192.168.1.1',
                'hostname': None,
                'status': 'active',
                'ssh_port': 22
            }
        ]
        
        results = self.scanner.scan_range('192.168.1.0/30', 22, use_nmap=False)
        
        assert len(results) == 1
        assert results[0]['status'] == 'active'
        mock_concurrent_scan.assert_called_once()
    
    def test_scan_range_invalid_ip_range(self):
        """Test scan_range with invalid IP range"""
        results = self.scanner.scan_range('invalid-range', 22)
        
        assert len(results) == 0
    
    @patch('netscan.scanner.network.nmap.PortScanner')
    def test_nmap_scan_success(self, mock_port_scanner):
        """Test successful nmap scan"""
        # Mock nmap scan result
        mock_nm = Mock()
        mock_scan_result = {
            'scan': {
                '192.168.1.100': {
                    'hostname': 'host1',
                    'status': {'state': 'up'},
                    'tcp': {
                        22: {
                            'state': 'open',
                            'name': 'ssh'
                        }
                    }
                }
            }
        }
        mock_nm.scan.return_value = mock_scan_result
        mock_port_scanner.return_value = mock_nm
        
        # Create new scanner instance to use mocked nmap
        scanner = NetworkScanner()
        scanner.nm = mock_nm
        
        results = scanner.nmap_scan('192.168.1.0/24', '22')
        
        assert len(results) == 1
        assert results[0]['ip_address'] == '192.168.1.100'
        assert results[0]['hostname'] == 'host1'
        assert results[0]['status'] == 'active'
        assert results[0]['ssh_banner'] == 'ssh'
    
    @patch('netscan.scanner.network.nmap.PortScanner')
    def test_nmap_scan_host_down(self, mock_port_scanner):
        """Test nmap scan with host down"""
        # Mock nmap scan result with host down
        mock_nm = Mock()
        mock_scan_result = {
            'scan': {
                '192.168.1.100': {
                    'hostname': 'host1',
                    'status': {'state': 'down'},
                    'tcp': {}
                }
            }
        }
        mock_nm.scan.return_value = mock_scan_result
        mock_port_scanner.return_value = mock_nm
        
        scanner = NetworkScanner()
        scanner.nm = mock_nm
        
        results = scanner.nmap_scan('192.168.1.0/24', '22')
        
        assert len(results) == 1
        assert results[0]['ip_address'] == '192.168.1.100'
        assert results[0]['status'] == 'inactive'
    
    @patch('netscan.scanner.network.nmap.PortScanner')
    def test_nmap_scan_exception(self, mock_port_scanner):
        """Test nmap scan with exception"""
        # Mock nmap scan exception
        mock_nm = Mock()
        mock_nm.scan.side_effect = Exception("nmap error")
        mock_port_scanner.return_value = mock_nm
        
        scanner = NetworkScanner()
        scanner.nm = mock_nm
        
        results = scanner.nmap_scan('192.168.1.0/24', '22')
        
        assert len(results) == 0
    
    def test_get_scan_summary_empty_results(self):
        """Test scan summary with empty results"""
        results = []
        summary = self.scanner.get_scan_summary(results)
        
        assert summary['total_hosts'] == 0
        assert summary['active_hosts'] == 0
        assert summary['inactive_hosts'] == 0
        assert summary['error_hosts'] == 0
        assert summary['timeout_hosts'] == 0
        assert summary['success_rate'] == 0.0
    
    def test_get_scan_summary_with_results(self):
        """Test scan summary with mixed results"""
        results = [
            {'status': 'active', 'response_time': 0.5},
            {'status': 'active', 'response_time': 1.0},
            {'status': 'inactive', 'response_time': 2.0},
            {'status': 'timeout', 'response_time': 5.0},
            {'status': 'error', 'response_time': None}
        ]
        
        summary = self.scanner.get_scan_summary(results)
        
        assert summary['total_hosts'] == 5
        assert summary['active_hosts'] == 2
        assert summary['inactive_hosts'] == 1
        assert summary['error_hosts'] == 1
        assert summary['timeout_hosts'] == 1
        assert summary['success_rate'] == 40.0  # 2/5 * 100
        assert summary['avg_response_time'] == 2.125  # (0.5+1.0+2.0+5.0)/4
    
    def test_scanner_thread_configuration(self):
        """Test scanner with different thread configurations"""
        # Test with high thread count
        high_thread_scanner = NetworkScanner(timeout=5, threads=50)
        assert high_thread_scanner.threads == 50
        
        # Test with low thread count
        low_thread_scanner = NetworkScanner(timeout=5, threads=1)
        assert low_thread_scanner.threads == 1
    
    def test_scanner_timeout_configuration(self):
        """Test scanner with different timeout configurations"""
        # Test with high timeout
        high_timeout_scanner = NetworkScanner(timeout=30, threads=10)
        assert high_timeout_scanner.timeout == 30
        
        # Test with low timeout
        low_timeout_scanner = NetworkScanner(timeout=1, threads=10)
        assert low_timeout_scanner.timeout == 1
    
    @patch('time.time')
    @patch('socket.socket')
    def test_response_time_calculation(self, mock_socket, mock_time):
        """Test response time calculation accuracy"""
        # Mock time progression
        mock_time.side_effect = [1000.0, 1001.5]  # 1.5 second difference
        
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b'SSH-2.0-Test'
        mock_socket.return_value = mock_sock
        
        result = self.scanner.check_ssh_port('192.168.1.100', 22)
        
        assert result['response_time'] == 1.5
    
    @patch('netscan.scanner.network.NetworkScanner.check_ssh_port')
    def test_concurrent_scan_progress_tracking(self, mock_check_ssh_port):
        """Test that concurrent scan tracks progress correctly"""
        # Mock multiple scan results
        mock_check_ssh_port.side_effect = [
            {'ip_address': f'192.168.1.{i}', 'ssh_port': 22, 'status': 'active', 'response_time': 0.5}
            for i in range(1, 101)  # 100 hosts
        ]
        
        ip_list = [f'192.168.1.{i}' for i in range(1, 101)]
        results = self.scanner.concurrent_scan(ip_list, 22)
        
        assert len(results) == 100
        assert all(r['status'] == 'active' for r in results)
        assert mock_check_ssh_port.call_count == 100
    
    def test_scanner_performance_with_large_range(self):
        """Test scanner performance characteristics"""
        # This test ensures the scanner can handle large IP ranges
        # without running out of memory or taking too long
        
        large_range = '10.0.0.0/22'  # 1024 addresses
        ip_list = self.scanner.expand_ip_range(large_range)
        
        # Should handle large ranges without memory issues
        assert len(ip_list) == 1022  # Network and broadcast addresses excluded
        assert isinstance(ip_list, list)
        assert all(isinstance(ip, str) for ip in ip_list)


class TestNetworkScannerIntegration:
    """Integration tests for NetworkScanner"""
    
    def setup_method(self):
        """Setup test scanner for each test"""
        self.scanner = NetworkScanner(timeout=1, threads=2)
    
    def test_localhost_scan_integration(self):
        """Integration test scanning localhost"""
        # This test actually tries to connect to localhost
        # Results will vary based on system configuration
        
        results = self.scanner.scan_range('127.0.0.1/32', 22, use_nmap=False)
        
        assert len(results) == 1
        assert results[0]['ip_address'] == '127.0.0.1'
        assert results[0]['ssh_port'] == 22
        assert results[0]['status'] in ['active', 'inactive', 'timeout', 'error']
        assert results[0]['response_time'] is not None
    
    def test_unreachable_network_integration(self):
        """Integration test scanning unreachable network"""
        # Use a private network range that's unlikely to exist
        results = self.scanner.scan_range('192.0.2.0/30', 22, use_nmap=False)
        
        # Should get results but likely inactive/timeout
        assert len(results) == 2  # .1 and .2 from /30
        assert all(r['status'] in ['inactive', 'timeout', 'error'] for r in results)
    
    def test_scan_summary_integration(self):
        """Integration test for scan summary generation"""
        # Scan localhost
        results = self.scanner.scan_range('127.0.0.1/32', 22, use_nmap=False)
        summary = self.scanner.get_scan_summary(results)
        
        assert summary['total_hosts'] == 1
        assert summary['active_hosts'] + summary['inactive_hosts'] + summary['error_hosts'] + summary['timeout_hosts'] == 1
        assert 0.0 <= summary['success_rate'] <= 100.0
        assert summary['avg_response_time'] >= 0.0 