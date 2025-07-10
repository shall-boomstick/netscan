"""
Performance tests for NetScan

These tests measure and validate the performance characteristics of the NetScan system
under various load conditions.
"""

import pytest
import time
import threading
import concurrent.futures
import psutil
import tempfile
from unittest.mock import patch, Mock

from netscan.database.operations import DatabaseManager
from netscan.scanner.network import NetworkScanner
from netscan.config import ConfigManager
from netscan.reporting.formatter import ReportFormatter
from netscan.reporting.exporter import ReportExporter
from tests import TestHelper, TEST_HOST_DATA


class TestPerformanceBenchmarks:
    """Performance benchmark tests"""
    
    def setup_method(self):
        """Setup test environment"""
        self.test_db_path = TestHelper.create_test_database()
        self.test_config_dir = TestHelper.create_test_config_dir()
        
        self.db_manager = DatabaseManager(self.test_db_path)
        self.db_manager.init_database()
        
        self.scanner = NetworkScanner(timeout=1, threads=10)
        self.report_formatter = ReportFormatter()
        self.report_exporter = ReportExporter()
    
    def teardown_method(self):
        """Clean up test environment"""
        TestHelper.cleanup_test_file(self.test_db_path)
        TestHelper.cleanup_test_dir(self.test_config_dir)
    
    def test_database_performance_bulk_insert(self):
        """Test database performance with bulk inserts"""
        host_count = 1000
        
        # Measure bulk insert performance
        start_time = time.time()
        
        created_hosts = []
        for i in range(host_count):
            host_data = TEST_HOST_DATA.copy()
            host_data['ip_address'] = f'192.168.{i//255}.{i%255}'
            host_data['hostname'] = f'host-{i}'
            
            host = self.db_manager.create_host(host_data)
            created_hosts.append(host)
        
        insert_time = time.time() - start_time
        
        # Performance assertions
        assert len(created_hosts) == host_count
        assert insert_time < 30.0  # Should complete within 30 seconds
        
        # Calculate throughput
        throughput = host_count / insert_time
        assert throughput > 30  # Should insert at least 30 hosts per second
        
        print(f"Bulk insert performance: {throughput:.2f} hosts/second")
    
    def test_database_performance_bulk_query(self):
        """Test database performance with bulk queries"""
        # Create test data
        host_count = 500
        for i in range(host_count):
            host_data = TEST_HOST_DATA.copy()
            host_data['ip_address'] = f'192.168.{i//255}.{i%255}'
            host_data['hostname'] = f'host-{i}'
            self.db_manager.create_host(host_data)
        
        # Test bulk query performance
        start_time = time.time()
        
        query_count = 100
        for i in range(query_count):
            hosts = self.db_manager.get_all_hosts()
            assert len(hosts) == host_count
        
        query_time = time.time() - start_time
        
        # Performance assertions
        assert query_time < 10.0  # Should complete within 10 seconds
        
        throughput = query_count / query_time
        assert throughput > 10  # Should perform at least 10 queries per second
        
        print(f"Bulk query performance: {throughput:.2f} queries/second")
    
    def test_database_performance_concurrent_operations(self):
        """Test database performance under concurrent load"""
        operation_count = 100
        thread_count = 10
        
        def database_worker():
            worker_results = []
            for i in range(operation_count // thread_count):
                # Create host
                host_data = TEST_HOST_DATA.copy()
                host_data['ip_address'] = f'192.168.{threading.current_thread().ident % 255}.{i}'
                host_data['hostname'] = f'host-{threading.current_thread().ident}-{i}'
                
                host = self.db_manager.create_host(host_data)
                worker_results.append(host)
                
                # Query hosts
                hosts = self.db_manager.get_all_hosts()
                assert len(hosts) >= len(worker_results)
            
            return worker_results
        
        # Measure concurrent performance
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(database_worker) for _ in range(thread_count)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        concurrent_time = time.time() - start_time
        
        # Performance assertions
        total_operations = sum(len(result) for result in results)
        assert total_operations == operation_count
        assert concurrent_time < 20.0  # Should complete within 20 seconds
        
        throughput = total_operations / concurrent_time
        assert throughput > 5  # Should handle at least 5 operations per second under load
        
        print(f"Concurrent database performance: {throughput:.2f} operations/second")
    
    def test_network_scanner_performance(self):
        """Test network scanner performance"""
        # Mock network operations for consistent timing
        with patch.object(self.scanner, 'check_ssh_port') as mock_check:
            mock_check.return_value = {
                'ip_address': '192.168.1.100',
                'ssh_port': 22,
                'status': 'active',
                'hostname': 'test-host',
                'response_time': 0.1
            }
            
            # Test scanning performance
            ip_count = 1000
            ip_list = [f'192.168.{i//255}.{i%255}' for i in range(ip_count)]
            
            start_time = time.time()
            results = self.scanner.concurrent_scan(ip_list, 22)
            scan_time = time.time() - start_time
            
            # Performance assertions
            assert len(results) == ip_count
            assert scan_time < 60.0  # Should complete within 60 seconds
            
            throughput = ip_count / scan_time
            assert throughput > 50  # Should scan at least 50 IPs per second
            
            print(f"Network scanner performance: {throughput:.2f} IPs/second")
    
    def test_reporting_performance(self):
        """Test reporting system performance"""
        # Create test data
        host_count = 1000
        hosts = []
        for i in range(host_count):
            host_data = TEST_HOST_DATA.copy()
            host_data['ip_address'] = f'192.168.{i//255}.{i%255}'
            host_data['hostname'] = f'host-{i}'
            
            host = self.db_manager.create_host(host_data)
            hosts.append(host)
        
        # Test table formatting performance
        start_time = time.time()
        table_data = self.report_formatter.format_hosts_table(hosts)
        table_time = time.time() - start_time
        
        assert table_data is not None
        assert table_time < 5.0  # Should complete within 5 seconds
        
        # Test export performance
        start_time = time.time()
        json_data = self.report_exporter.export_hosts_json(hosts)
        export_time = time.time() - start_time
        
        assert json_data is not None
        assert export_time < 5.0  # Should complete within 5 seconds
        
        print(f"Table formatting performance: {host_count/table_time:.2f} hosts/second")
        print(f"JSON export performance: {host_count/export_time:.2f} hosts/second")
    
    def test_memory_usage_under_load(self):
        """Test memory usage under load"""
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create large dataset
        host_count = 5000
        hosts = []
        
        for i in range(host_count):
            host_data = TEST_HOST_DATA.copy()
            host_data['ip_address'] = f'192.168.{i//255}.{i%255}'
            host_data['hostname'] = f'host-{i}'
            
            host = self.db_manager.create_host(host_data)
            hosts.append(host)
            
            # Monitor memory usage periodically
            if i % 1000 == 0:
                current_memory = process.memory_info().rss / 1024 / 1024  # MB
                memory_growth = current_memory - initial_memory
                
                # Memory should not grow excessively
                assert memory_growth < 500  # Should not exceed 500MB growth
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        total_memory_growth = final_memory - initial_memory
        
        print(f"Memory usage: {initial_memory:.2f} MB -> {final_memory:.2f} MB (+{total_memory_growth:.2f} MB)")
        
        # Memory growth should be reasonable
        assert total_memory_growth < 1000  # Should not exceed 1GB growth
    
    def test_cpu_usage_under_load(self):
        """Test CPU usage under load"""
        # Monitor CPU usage during intensive operations
        def cpu_monitor():
            cpu_usage = []
            for _ in range(10):
                cpu_usage.append(psutil.cpu_percent(interval=0.1))
            return max(cpu_usage)
        
        # Start CPU monitoring
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            cpu_future = executor.submit(cpu_monitor)
            
            # Perform intensive operations
            with patch.object(self.scanner, 'check_ssh_port') as mock_check:
                mock_check.return_value = {
                    'ip_address': '192.168.1.100',
                    'ssh_port': 22,
                    'status': 'active',
                    'hostname': 'test-host',
                    'response_time': 0.1
                }
                
                # Intensive network scanning
                ip_list = [f'192.168.{i//255}.{i%255}' for i in range(1000)]
                results = self.scanner.concurrent_scan(ip_list, 22)
            
            max_cpu_usage = cpu_future.result()
        
        print(f"Max CPU usage during intensive operations: {max_cpu_usage:.2f}%")
        
        # CPU usage should be reasonable (not hitting 100% constantly)
        assert max_cpu_usage < 95.0  # Should not exceed 95% CPU usage
    
    def test_disk_io_performance(self):
        """Test disk I/O performance"""
        # Monitor disk I/O during database operations
        initial_io = psutil.disk_io_counters()
        
        # Perform disk-intensive operations
        host_count = 2000
        
        start_time = time.time()
        for i in range(host_count):
            host_data = TEST_HOST_DATA.copy()
            host_data['ip_address'] = f'192.168.{i//255}.{i%255}'
            host_data['hostname'] = f'host-{i}'
            
            host = self.db_manager.create_host(host_data)
            
            # Create scan history
            scan_data = {
                'host_id': host.id,
                'scan_type': 'network',
                'result': 'success',
                'scan_duration': 1.0
            }
            self.db_manager.create_scan_history(scan_data)
        
        operation_time = time.time() - start_time
        final_io = psutil.disk_io_counters()
        
        # Calculate I/O metrics
        read_bytes = final_io.read_bytes - initial_io.read_bytes
        write_bytes = final_io.write_bytes - initial_io.write_bytes
        
        print(f"Disk I/O performance: {read_bytes/1024/1024:.2f} MB read, {write_bytes/1024/1024:.2f} MB written")
        print(f"I/O throughput: {(read_bytes + write_bytes)/1024/1024/operation_time:.2f} MB/s")
        
        # I/O should be reasonable
        total_io_mb = (read_bytes + write_bytes) / 1024 / 1024
        assert total_io_mb < 1000  # Should not exceed 1GB I/O for this test
    
    def test_concurrent_user_simulation(self):
        """Simulate concurrent users using the system"""
        user_count = 20
        operations_per_user = 50
        
        def simulate_user():
            user_results = []
            user_id = threading.current_thread().ident
            
            for i in range(operations_per_user):
                # Create host
                host_data = TEST_HOST_DATA.copy()
                host_data['ip_address'] = f'10.{user_id % 255}.{i // 255}.{i % 255}'
                host_data['hostname'] = f'user-{user_id}-host-{i}'
                
                host = self.db_manager.create_host(host_data)
                user_results.append(host)
                
                # Query hosts
                all_hosts = self.db_manager.get_all_hosts()
                
                # Create scan history
                scan_data = {
                    'host_id': host.id,
                    'scan_type': 'network',
                    'result': 'success',
                    'scan_duration': 1.0
                }
                self.db_manager.create_scan_history(scan_data)
                
                # Generate report periodically
                if i % 10 == 0:
                    report_data = self.report_formatter.format_hosts_table([host])
                    assert report_data is not None
            
            return user_results
        
        # Simulate concurrent users
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=user_count) as executor:
            futures = [executor.submit(simulate_user) for _ in range(user_count)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        total_time = time.time() - start_time
        
        # Verify results
        total_operations = sum(len(result) for result in results)
        expected_operations = user_count * operations_per_user
        
        assert total_operations == expected_operations
        assert total_time < 120.0  # Should complete within 2 minutes
        
        throughput = total_operations / total_time
        print(f"Concurrent user simulation: {throughput:.2f} operations/second with {user_count} users")
        
        # Should handle reasonable concurrent load
        assert throughput > 10  # Should handle at least 10 operations per second
    
    def test_scalability_limits(self):
        """Test system scalability limits"""
        # Test with increasing load to find limits
        load_levels = [100, 500, 1000, 2000]
        performance_results = []
        
        for load_level in load_levels:
            # Create test data
            hosts = []
            
            start_time = time.time()
            for i in range(load_level):
                host_data = TEST_HOST_DATA.copy()
                host_data['ip_address'] = f'172.16.{i//255}.{i%255}'
                host_data['hostname'] = f'scale-host-{i}'
                
                host = self.db_manager.create_host(host_data)
                hosts.append(host)
            
            create_time = time.time() - start_time
            
            # Test query performance at this scale
            start_time = time.time()
            all_hosts = self.db_manager.get_all_hosts()
            query_time = time.time() - start_time
            
            # Test reporting performance at this scale
            start_time = time.time()
            report_data = self.report_formatter.format_hosts_table(all_hosts)
            report_time = time.time() - start_time
            
            performance_results.append({
                'load_level': load_level,
                'create_time': create_time,
                'query_time': query_time,
                'report_time': report_time,
                'create_throughput': load_level / create_time,
                'query_throughput': load_level / query_time,
                'report_throughput': load_level / report_time
            })
            
            # Clean up for next test
            # (In a real scenario, you might want to keep data for cumulative testing)
            
        # Analyze performance degradation
        print("\nScalability test results:")
        for result in performance_results:
            print(f"Load {result['load_level']}: "
                  f"Create {result['create_throughput']:.2f}/s, "
                  f"Query {result['query_throughput']:.2f}/s, "
                  f"Report {result['report_throughput']:.2f}/s")
        
        # Performance should degrade gracefully
        for i in range(1, len(performance_results)):
            prev_result = performance_results[i-1]
            curr_result = performance_results[i]
            
            # Throughput should not drop dramatically (less than 50% at each step)
            create_ratio = curr_result['create_throughput'] / prev_result['create_throughput']
            query_ratio = curr_result['query_throughput'] / prev_result['query_throughput']
            
            assert create_ratio > 0.3  # Should not drop below 30% of previous performance
            assert query_ratio > 0.3   # Should not drop below 30% of previous performance


class TestPerformanceRegression:
    """Performance regression tests"""
    
    def setup_method(self):
        """Setup test environment"""
        self.test_db_path = TestHelper.create_test_database()
        self.db_manager = DatabaseManager(self.test_db_path)
        self.db_manager.init_database()
    
    def teardown_method(self):
        """Clean up test environment"""
        TestHelper.cleanup_test_file(self.test_db_path)
    
    def test_database_query_performance_regression(self):
        """Test for database query performance regression"""
        # Create baseline dataset
        baseline_host_count = 1000
        for i in range(baseline_host_count):
            host_data = TEST_HOST_DATA.copy()
            host_data['ip_address'] = f'192.168.{i//255}.{i%255}'
            host_data['hostname'] = f'baseline-host-{i}'
            self.db_manager.create_host(host_data)
        
        # Measure baseline performance
        query_count = 100
        start_time = time.time()
        
        for _ in range(query_count):
            hosts = self.db_manager.get_all_hosts()
            assert len(hosts) == baseline_host_count
        
        baseline_time = time.time() - start_time
        baseline_throughput = query_count / baseline_time
        
        # Add more data to simulate growth
        additional_host_count = 1000
        for i in range(additional_host_count):
            host_data = TEST_HOST_DATA.copy()
            host_data['ip_address'] = f'10.0.{i//255}.{i%255}'
            host_data['hostname'] = f'additional-host-{i}'
            self.db_manager.create_host(host_data)
        
        # Measure performance after growth
        start_time = time.time()
        
        for _ in range(query_count):
            hosts = self.db_manager.get_all_hosts()
            assert len(hosts) == baseline_host_count + additional_host_count
        
        current_time = time.time() - start_time
        current_throughput = query_count / current_time
        
        # Performance should not degrade significantly
        performance_ratio = current_throughput / baseline_throughput
        
        print(f"Performance regression test: {performance_ratio:.2f} ratio")
        print(f"Baseline: {baseline_throughput:.2f} queries/second")
        print(f"Current: {current_throughput:.2f} queries/second")
        
        # Should maintain at least 70% of baseline performance
        assert performance_ratio > 0.7, f"Performance degraded too much: {performance_ratio:.2f}"
    
    def test_memory_usage_regression(self):
        """Test for memory usage regression"""
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create dataset and measure memory growth
        host_count = 2000
        memory_measurements = []
        
        for i in range(host_count):
            host_data = TEST_HOST_DATA.copy()
            host_data['ip_address'] = f'192.168.{i//255}.{i%255}'
            host_data['hostname'] = f'memory-test-host-{i}'
            
            self.db_manager.create_host(host_data)
            
            # Measure memory every 500 hosts
            if i % 500 == 0:
                current_memory = process.memory_info().rss / 1024 / 1024  # MB
                memory_growth = current_memory - initial_memory
                memory_measurements.append(memory_growth)
        
        # Memory growth should be linear, not exponential
        if len(memory_measurements) > 2:
            growth_rates = []
            for i in range(1, len(memory_measurements)):
                growth_rate = memory_measurements[i] - memory_measurements[i-1]
                growth_rates.append(growth_rate)
            
            # Growth rate should be relatively stable (no memory leaks)
            max_growth_rate = max(growth_rates)
            min_growth_rate = min(growth_rates)
            
            # Growth rate variation should not exceed 5x
            if min_growth_rate > 0:
                growth_rate_ratio = max_growth_rate / min_growth_rate
                assert growth_rate_ratio < 5.0, f"Memory growth rate too variable: {growth_rate_ratio:.2f}"
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        total_memory_growth = final_memory - initial_memory
        
        print(f"Memory usage regression test: {total_memory_growth:.2f} MB total growth")
        
        # Total memory growth should be reasonable
        assert total_memory_growth < 500, f"Memory usage too high: {total_memory_growth:.2f} MB" 