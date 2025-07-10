"""
Integration tests for the full NetScan system

These tests verify that all components work together correctly in realistic scenarios.
"""

import pytest
import tempfile
import os
import json
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from netscan.database.operations import DatabaseManager
from netscan.scanner.network import NetworkScanner
from netscan.config import ConfigManager
from netscan.reporting.formatter import ReportFormatter
from netscan.reporting.exporter import ReportExporter
from netscan.utils.error_handling import NetworkError, DatabaseError
from tests import TestHelper, TEST_HOST_DATA, TEST_SCAN_RESULTS


class TestFullSystemIntegration:
    """Integration tests for the complete NetScan system"""
    
    def setup_method(self):
        """Setup test environment for each test"""
        self.test_db_path = TestHelper.create_test_database()
        self.test_config_dir = TestHelper.create_test_config_dir()
        
        # Initialize components
        self.db_manager = DatabaseManager(self.test_db_path)
        self.db_manager.init_database()
        
        self.scanner = NetworkScanner(timeout=1, threads=2)
        self.report_formatter = ReportFormatter()
        self.report_exporter = ReportExporter()
        
        # Create test config
        self.config_manager = ConfigManager(config_dir=self.test_config_dir)
    
    def teardown_method(self):
        """Clean up test environment after each test"""
        TestHelper.cleanup_test_file(self.test_db_path)
        TestHelper.cleanup_test_dir(self.test_config_dir)
    
    def test_complete_scan_workflow(self):
        """Test complete scan workflow: scan -> store -> report"""
        # Mock network scanner results
        with patch.object(self.scanner, 'scan_range') as mock_scan:
            mock_scan.return_value = TEST_SCAN_RESULTS
            
            # 1. Perform scan
            scan_results = self.scanner.scan_range('192.168.1.0/30', 22, use_nmap=False)
            
            assert len(scan_results) == 3
            assert scan_results[0]['status'] == 'active'
            assert scan_results[1]['status'] == 'inactive'
            assert scan_results[2]['status'] == 'timeout'
            
            # 2. Store results in database
            stored_hosts = []
            for result in scan_results:
                if result['status'] == 'active':
                    host_data = {
                        'ip_address': result['ip_address'],
                        'hostname': result['hostname'],
                        'ssh_port': result['ssh_port'],
                        'status': result['status'],
                        'os_info': 'Unknown',
                        'kernel_version': 'Unknown',
                        'uptime': 'Unknown',
                        'cpu_info': 'Unknown',
                        'memory_total': 0,
                        'memory_used': 0,
                        'disk_usage': 'Unknown'
                    }
                    
                    host = self.db_manager.create_host(host_data)
                    stored_hosts.append(host)
                    
                    # Create scan history
                    scan_history_data = {
                        'host_id': host.id,
                        'scan_type': 'network',
                        'result': 'success',
                        'scan_duration': result['response_time']
                    }
                    self.db_manager.create_scan_history(scan_history_data)
            
            # 3. Verify data storage
            all_hosts = self.db_manager.get_all_hosts()
            assert len(all_hosts) == 1  # Only active host stored
            assert all_hosts[0].ip_address == '192.168.1.100'
            assert all_hosts[0].status == 'active'
            
            # 4. Generate reports
            report_data = self.report_formatter.format_hosts_table(all_hosts)
            assert report_data is not None
            
            # 5. Export data
            export_data = self.report_exporter.export_hosts_json(all_hosts)
            exported_hosts = json.loads(export_data)
            assert len(exported_hosts) == 1
            assert exported_hosts[0]['ip_address'] == '192.168.1.100'
    
    def test_configuration_integration(self):
        """Test configuration system integration"""
        # 1. Set configuration values
        self.config_manager.set_value('scanning.timeout', '10')
        self.config_manager.set_value('scanning.threads', '20')
        self.config_manager.set_value('database.path', 'test.db')
        
        # 2. Verify configuration persistence
        assert self.config_manager.get_value('scanning.timeout') == '10'
        assert self.config_manager.get_value('scanning.threads') == '20'
        assert self.config_manager.get_value('database.path') == 'test.db'
        
        # 3. Test configuration sections
        scanning_section = self.config_manager.get_section('scanning')
        assert scanning_section['timeout'] == '10'
        assert scanning_section['threads'] == '20'
        
        # 4. Test configuration export/import
        export_data = self.config_manager.export_config()
        assert 'scanning' in export_data
        assert 'database' in export_data
        
        # 5. Test configuration validation
        is_valid = self.config_manager.validate_config()
        assert is_valid is True
    
    def test_error_handling_integration(self):
        """Test error handling across system components"""
        # 1. Test database error recovery
        with patch.object(self.db_manager, 'get_session') as mock_session:
            mock_session.side_effect = Exception("Database connection failed")
            
            with pytest.raises(DatabaseError):
                self.db_manager.create_host(TEST_HOST_DATA)
        
        # 2. Test network error handling
        with patch.object(self.scanner, 'check_ssh_port') as mock_check:
            mock_check.side_effect = NetworkError("Network unreachable")
            
            # Should handle error gracefully
            results = self.scanner.concurrent_scan(['192.168.1.100'], 22)
            assert len(results) == 1
            assert results[0]['status'] == 'error'
            assert 'Network unreachable' in results[0]['error']
        
        # 3. Test configuration error handling
        with patch.object(self.config_manager, 'load_config') as mock_load:
            mock_load.side_effect = Exception("Config file corrupted")
            
            # Should fallback to defaults
            config = ConfigManager(config_dir=self.test_config_dir)
            assert config.get_value('scanning.timeout') == '5'  # Default value
    
    def test_performance_with_large_dataset(self):
        """Test system performance with large dataset"""
        # 1. Create large dataset
        hosts_data = []
        for i in range(100):
            host_data = TEST_HOST_DATA.copy()
            host_data['ip_address'] = f'192.168.1.{i}'
            host_data['hostname'] = f'host-{i}'
            hosts_data.append(host_data)
        
        # 2. Bulk insert hosts
        created_hosts = []
        for host_data in hosts_data:
            host = self.db_manager.create_host(host_data)
            created_hosts.append(host)
        
        # 3. Verify all hosts created
        all_hosts = self.db_manager.get_all_hosts()
        assert len(all_hosts) == 100
        
        # 4. Test filtering performance
        active_hosts = self.db_manager.get_hosts_with_filters(status='active')
        assert len(active_hosts) == 100
        
        # 5. Test reporting performance
        report_data = self.report_formatter.format_hosts_table(all_hosts)
        assert report_data is not None
        
        # 6. Test export performance
        export_data = self.report_exporter.export_hosts_json(all_hosts)
        exported_hosts = json.loads(export_data)
        assert len(exported_hosts) == 100
    
    def test_concurrent_operations(self):
        """Test concurrent operations across components"""
        import threading
        import time
        
        results = []
        errors = []
        
        def create_host_worker(host_id):
            try:
                host_data = TEST_HOST_DATA.copy()
                host_data['ip_address'] = f'192.168.1.{host_id}'
                host_data['hostname'] = f'host-{host_id}'
                
                host = self.db_manager.create_host(host_data)
                results.append(host)
            except Exception as e:
                errors.append(e)
        
        # Create multiple threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=create_host_worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Verify results
        assert len(results) == 10
        assert len(errors) == 0
        
        # Verify database consistency
        all_hosts = self.db_manager.get_all_hosts()
        assert len(all_hosts) == 10
        
        ip_addresses = [host.ip_address for host in all_hosts]
        expected_ips = [f'192.168.1.{i}' for i in range(10)]
        assert set(ip_addresses) == set(expected_ips)
    
    def test_data_consistency_across_components(self):
        """Test data consistency across different components"""
        # 1. Create hosts through database manager
        host1 = self.db_manager.create_host(TEST_HOST_DATA)
        
        host2_data = TEST_HOST_DATA.copy()
        host2_data['ip_address'] = '192.168.1.101'
        host2_data['hostname'] = 'host2'
        host2 = self.db_manager.create_host(host2_data)
        
        # 2. Create scan history
        scan_data = {
            'host_id': host1.id,
            'scan_type': 'network',
            'result': 'success',
            'scan_duration': 1.5
        }
        scan_history = self.db_manager.create_scan_history(scan_data)
        
        # 3. Verify consistency through different access methods
        # Direct database access
        db_hosts = self.db_manager.get_all_hosts()
        assert len(db_hosts) == 2
        
        # Filtered access
        active_hosts = self.db_manager.get_hosts_with_filters(status='active')
        assert len(active_hosts) == 2
        
        # Scan history access
        host1_history = self.db_manager.get_scan_history_for_host(host1.id)
        assert len(host1_history) == 1
        assert host1_history[0].result == 'success'
        
        # 4. Test reporting consistency
        report_data = self.report_formatter.format_hosts_table(db_hosts)
        assert report_data is not None
        
        # 5. Test export consistency
        export_data = self.report_exporter.export_hosts_json(db_hosts)
        exported_hosts = json.loads(export_data)
        assert len(exported_hosts) == 2
        
        # Verify exported data matches database data
        exported_ips = [host['ip_address'] for host in exported_hosts]
        db_ips = [host.ip_address for host in db_hosts]
        assert set(exported_ips) == set(db_ips)
    
    def test_configuration_effects_on_system(self):
        """Test how configuration changes affect system behavior"""
        # 1. Set specific configuration
        self.config_manager.set_value('scanning.timeout', '2')
        self.config_manager.set_value('scanning.threads', '1')
        
        # 2. Create scanner with config
        scanner = NetworkScanner(
            timeout=int(self.config_manager.get_value('scanning.timeout')),
            threads=int(self.config_manager.get_value('scanning.threads'))
        )
        
        # 3. Verify scanner uses configuration
        assert scanner.timeout == 2
        assert scanner.threads == 1
        
        # 4. Change configuration
        self.config_manager.set_value('scanning.timeout', '10')
        self.config_manager.set_value('scanning.threads', '5')
        
        # 5. Create new scanner with updated config
        scanner2 = NetworkScanner(
            timeout=int(self.config_manager.get_value('scanning.timeout')),
            threads=int(self.config_manager.get_value('scanning.threads'))
        )
        
        # 6. Verify new scanner uses updated configuration
        assert scanner2.timeout == 10
        assert scanner2.threads == 5
    
    def test_system_recovery_from_failures(self):
        """Test system recovery from various failure scenarios"""
        # 1. Test recovery from database corruption
        # Create some data first
        original_host = self.db_manager.create_host(TEST_HOST_DATA)
        
        # Simulate database corruption by closing connection
        if hasattr(self.db_manager, 'engine'):
            self.db_manager.engine.dispose()
        
        # System should be able to reinitialize
        self.db_manager.init_database()
        
        # Data should still be accessible
        recovered_host = self.db_manager.get_host_by_ip(TEST_HOST_DATA['ip_address'])
        assert recovered_host is not None
        assert recovered_host.ip_address == original_host.ip_address
        
        # 2. Test recovery from configuration issues
        # Create invalid configuration
        invalid_config_path = os.path.join(self.test_config_dir, 'invalid.conf')
        with open(invalid_config_path, 'w') as f:
            f.write("invalid configuration content")
        
        # System should fallback to defaults
        config = ConfigManager(config_dir=self.test_config_dir)
        assert config.get_value('scanning.timeout') == '5'  # Default value
        
        # 3. Test recovery from network failures
        with patch.object(self.scanner, 'check_ssh_port') as mock_check:
            mock_check.side_effect = [
                NetworkError("Network error"),
                {'ip_address': '192.168.1.100', 'ssh_port': 22, 'status': 'active', 'response_time': 1.0}
            ]
            
            # First call should fail, second should succeed
            results = []
            
            # First scan - should handle error
            result1 = self.scanner.concurrent_scan(['192.168.1.100'], 22)
            results.extend(result1)
            
            # Second scan - should succeed
            result2 = self.scanner.concurrent_scan(['192.168.1.100'], 22)
            results.extend(result2)
            
            assert len(results) == 2
            assert results[0]['status'] == 'error'
            assert results[1]['status'] == 'active'
    
    def test_system_state_consistency(self):
        """Test system state consistency across operations"""
        # 1. Initial state
        initial_hosts = self.db_manager.get_all_hosts()
        initial_count = len(initial_hosts)
        
        # 2. Add hosts through different methods
        # Method 1: Direct database insertion
        host1 = self.db_manager.create_host(TEST_HOST_DATA)
        
        # Method 2: Simulated scan result storage
        scan_result = {
            'ip_address': '192.168.1.101',
            'hostname': 'scanned-host',
            'ssh_port': 22,
            'status': 'active',
            'response_time': 1.5
        }
        
        host2_data = {
            'ip_address': scan_result['ip_address'],
            'hostname': scan_result['hostname'],
            'ssh_port': scan_result['ssh_port'],
            'status': scan_result['status'],
            'os_info': 'Unknown',
            'kernel_version': 'Unknown',
            'uptime': 'Unknown',
            'cpu_info': 'Unknown',
            'memory_total': 0,
            'memory_used': 0,
            'disk_usage': 'Unknown'
        }
        host2 = self.db_manager.create_host(host2_data)
        
        # 3. Verify state consistency
        final_hosts = self.db_manager.get_all_hosts()
        assert len(final_hosts) == initial_count + 2
        
        # 4. Test cross-component consistency
        # Get data through different interfaces
        db_hosts = self.db_manager.get_all_hosts()
        active_hosts = self.db_manager.get_hosts_with_filters(status='active')
        
        # Should have consistent counts
        assert len(db_hosts) == len(active_hosts)  # All test hosts are active
        
        # 5. Test reporting consistency
        report_hosts = self.report_formatter.format_hosts_table(db_hosts)
        export_data = self.report_exporter.export_hosts_json(db_hosts)
        exported_hosts = json.loads(export_data)
        
        # Should have consistent data
        assert len(exported_hosts) == len(db_hosts)
        
        # Verify IDs match
        db_ips = sorted([host.ip_address for host in db_hosts])
        exported_ips = sorted([host['ip_address'] for host in exported_hosts])
        assert db_ips == exported_ips


class TestSystemEdgeCases:
    """Test edge cases and boundary conditions"""
    
    def setup_method(self):
        """Setup test environment"""
        self.test_db_path = TestHelper.create_test_database()
        self.test_config_dir = TestHelper.create_test_config_dir()
        
        self.db_manager = DatabaseManager(self.test_db_path)
        self.db_manager.init_database()
        
        self.scanner = NetworkScanner(timeout=1, threads=2)
        self.config_manager = ConfigManager(config_dir=self.test_config_dir)
    
    def teardown_method(self):
        """Clean up test environment"""
        TestHelper.cleanup_test_file(self.test_db_path)
        TestHelper.cleanup_test_dir(self.test_config_dir)
    
    def test_empty_database_operations(self):
        """Test operations on empty database"""
        # Test getting hosts from empty database
        hosts = self.db_manager.get_all_hosts()
        assert len(hosts) == 0
        
        # Test getting non-existent host
        host = self.db_manager.get_host_by_ip('192.168.1.100')
        assert host is None
        
        # Test filtering empty database
        active_hosts = self.db_manager.get_hosts_with_filters(status='active')
        assert len(active_hosts) == 0
        
        # Test getting stats from empty database
        stats = self.db_manager.get_database_stats()
        assert stats['total_hosts'] == 0
        assert stats['active_hosts'] == 0
        assert stats['total_scans'] == 0
    
    def test_invalid_ip_ranges(self):
        """Test scanner with invalid IP ranges"""
        invalid_ranges = [
            '',  # Empty string
            '256.256.256.256/24',  # Invalid IP
            '192.168.1.0/33',  # Invalid CIDR
            'not-an-ip',  # Non-IP string
            '192.168.1.0/24/extra'  # Malformed CIDR
        ]
        
        for invalid_range in invalid_ranges:
            results = self.scanner.scan_range(invalid_range, 22)
            assert len(results) == 0
    
    def test_boundary_values(self):
        """Test boundary values for various parameters"""
        # Test scanner with boundary timeout values
        scanner_min = NetworkScanner(timeout=1, threads=1)
        assert scanner_min.timeout == 1
        assert scanner_min.threads == 1
        
        scanner_max = NetworkScanner(timeout=300, threads=100)
        assert scanner_max.timeout == 300
        assert scanner_max.threads == 100
        
        # Test with zero threads (should handle gracefully)
        scanner_zero = NetworkScanner(timeout=5, threads=0)
        # Should not crash, might default to 1 or handle gracefully
        assert scanner_zero.threads >= 0
    
    def test_unicode_and_special_characters(self):
        """Test handling of unicode and special characters"""
        # Test host with unicode hostname
        unicode_host_data = TEST_HOST_DATA.copy()
        unicode_host_data['hostname'] = 'høst-ñame-测试'
        unicode_host_data['ip_address'] = '192.168.1.200'
        
        host = self.db_manager.create_host(unicode_host_data)
        assert host.hostname == 'høst-ñame-测试'
        
        # Test retrieving unicode host
        retrieved_host = self.db_manager.get_host_by_ip('192.168.1.200')
        assert retrieved_host.hostname == 'høst-ñame-测试'
        
        # Test special characters in OS info
        special_host_data = TEST_HOST_DATA.copy()
        special_host_data['ip_address'] = '192.168.1.201'
        special_host_data['os_info'] = 'Ubuntu 20.04 LTS (Focal Fossa) - Special chars: @#$%^&*()'
        
        host = self.db_manager.create_host(special_host_data)
        assert '@#$%^&*()' in host.os_info
    
    def test_large_data_values(self):
        """Test handling of large data values"""
        # Test with large memory values
        large_host_data = TEST_HOST_DATA.copy()
        large_host_data['ip_address'] = '192.168.1.202'
        large_host_data['memory_total'] = 1024 * 1024 * 1024  # 1TB in MB
        large_host_data['memory_used'] = 512 * 1024 * 1024   # 512GB in MB
        
        host = self.db_manager.create_host(large_host_data)
        assert host.memory_total == 1024 * 1024 * 1024
        assert host.memory_used == 512 * 1024 * 1024
        
        # Test with very long strings
        long_host_data = TEST_HOST_DATA.copy()
        long_host_data['ip_address'] = '192.168.1.203'
        long_host_data['uptime'] = 'Very long uptime string: ' + 'x' * 1000
        
        host = self.db_manager.create_host(long_host_data)
        assert len(host.uptime) > 1000
    
    def test_concurrent_duplicate_operations(self):
        """Test concurrent operations that might create duplicates"""
        import threading
        
        results = []
        errors = []
        
        def create_same_host():
            try:
                host = self.db_manager.create_host(TEST_HOST_DATA)
                results.append(host)
            except Exception as e:
                errors.append(e)
        
        # Create multiple threads trying to create the same host
        threads = []
        for i in range(5):
            thread = threading.Thread(target=create_same_host)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Should have 5 results (all should succeed due to upsert behavior)
        assert len(results) == 5
        assert len(errors) == 0
        
        # But only one host should exist in database
        all_hosts = self.db_manager.get_all_hosts()
        assert len(all_hosts) == 1
        assert all_hosts[0].ip_address == TEST_HOST_DATA['ip_address']
    
    def test_system_resource_limits(self):
        """Test system behavior at resource limits"""
        # Test with many database connections
        sessions = []
        try:
            for i in range(50):
                session = self.db_manager.get_session()
                sessions.append(session)
            
            # Should be able to create many sessions
            assert len(sessions) == 50
            
        finally:
            # Clean up sessions
            for session in sessions:
                session.close()
        
        # Test with many concurrent operations
        import threading
        
        results = []
        
        def bulk_create_hosts():
            for i in range(10):
                host_data = TEST_HOST_DATA.copy()
                host_data['ip_address'] = f'192.168.{threading.current_thread().ident % 255}.{i}'
                host = self.db_manager.create_host(host_data)
                results.append(host)
        
        # Create multiple threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=bulk_create_hosts)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Should have created all hosts
        assert len(results) == 100
        
        # Verify in database
        all_hosts = self.db_manager.get_all_hosts()
        assert len(all_hosts) == 100 