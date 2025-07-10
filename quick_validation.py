#!/usr/bin/env python3
"""
Quick NetScan Validation Script

Simple validation of core NetScan functionality without complex performance tests.
"""

import sys
import os
import tempfile
import json
from pathlib import Path

# Add the netscan module to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

def test_imports():
    """Test that all modules can be imported"""
    print("Testing imports...")
    
    try:
        from netscan.database.operations import DatabaseManager
        from netscan.scanner.network import NetworkScanner
        from netscan.config import ConfigManager
        from netscan.reporting.formatter import ReportFormatter
        from netscan.reporting.exporter import ReportExporter
        from netscan.utils.error_handling import NetworkError, DatabaseError
        from netscan.utils.logging import setup_logging, get_logger
        print("✓ All imports successful")
        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False

def test_database_basic():
    """Test basic database operations"""
    print("Testing database operations...")
    
    try:
        from netscan.database.operations import DatabaseManager
        
        # Create temporary database
        temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        temp_db.close()
        
        db = DatabaseManager(temp_db.name)
        
        # Test host creation
        host_data = {
            'ip_address': '192.168.1.100',
            'hostname': 'test-host',
            'ssh_port': 22,
            'status': 'active',
            'os_info': 'Ubuntu 22.04',
            'memory_total': 8192,
            'memory_used': 4096
        }
        
        host = db.create_host(host_data)
        assert host.ip_address == '192.168.1.100'
        
        # Test host retrieval
        retrieved = db.get_host_by_ip('192.168.1.100')
        assert retrieved is not None
        assert retrieved.hostname == 'test-host'
        
        # Test host listing
        all_hosts = db.get_all_hosts()
        assert len(all_hosts) >= 1
        
        # Test statistics
        stats = db.get_host_statistics()
        assert stats['total_hosts'] >= 1
        
        # Cleanup
        os.unlink(temp_db.name)
        
        print("✓ Database operations successful")
        return True
        
    except Exception as e:
        print(f"✗ Database test failed: {e}")
        return False

def test_network_scanner():
    """Test network scanner basic functionality"""
    print("Testing network scanner...")
    
    try:
        from netscan.scanner.network import NetworkScanner
        
        scanner = NetworkScanner(timeout=2, threads=2)
        
        # Test IP range validation
        assert scanner.validate_ip_range('192.168.1.0/24') == True
        assert scanner.validate_ip_range('invalid') == False
        
        # Test IP expansion
        ips = scanner.expand_ip_range('127.0.0.1/32')
        assert len(ips) == 1
        assert ips[0] == '127.0.0.1'
        
        print("✓ Network scanner operations successful")
        return True
        
    except Exception as e:
        print(f"✗ Network scanner test failed: {e}")
        return False

def test_config_manager():
    """Test configuration management"""
    print("Testing configuration management...")
    
    try:
        from netscan.config import ConfigManager
        
        # Create temporary config directory
        temp_dir = tempfile.mkdtemp()
        config = ConfigManager(config_dir=temp_dir)
        
        # Test configuration setting/getting
        config.set_value('scanning.timeout', '10')
        timeout = config.get_value('scanning.timeout')
        assert timeout == '10'
        
        # Test section retrieval
        section = config.get_section('scanning')
        assert 'timeout' in section
        
        print("✓ Configuration management successful")
        return True
        
    except Exception as e:
        print(f"✗ Configuration test failed: {e}")
        return False

def test_reporting():
    """Test reporting functionality"""
    print("Testing reporting...")
    
    try:
        from netscan.database.operations import DatabaseManager
        from netscan.reporting.formatter import ReportFormatter
        from netscan.reporting.exporter import ReportExporter
        
        # Create temporary database with test data
        temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        temp_db.close()
        
        db = DatabaseManager(temp_db.name)
        
        # Create test host
        host_data = {
            'ip_address': '192.168.1.200',
            'hostname': 'report-test',
            'ssh_port': 22,
            'status': 'active',
            'os_info': 'CentOS 7',
            'memory_total': 4096,
            'memory_used': 2048
        }
        
        host = db.create_host(host_data)
        hosts = [host]
        
        # Test formatter
        formatter = ReportFormatter()
        table = formatter.format_hosts_table(hosts)
        assert table is not None
        
        summary = formatter.format_summary(hosts)
        assert 'NetScan Summary Report' in summary
        
        # Test exporter
        exporter = ReportExporter()
        json_export = exporter.export_hosts_json(hosts)
        assert isinstance(json_export, str)
        
        # Verify JSON content
        data = json.loads(json_export)
        assert 'hosts' in data
        assert len(data['hosts']) == 1
        assert data['hosts'][0]['ip_address'] == '192.168.1.200'
        
        # Cleanup
        os.unlink(temp_db.name)
        
        print("✓ Reporting functionality successful")
        return True
        
    except Exception as e:
        print(f"✗ Reporting test failed: {e}")
        return False

def test_cli_integration():
    """Test CLI integration"""
    print("Testing CLI integration...")
    
    try:
        # Test that the main CLI module can be imported
        from netscan.__main__ import cli
        assert cli is not None
        
        print("✓ CLI integration successful")
        return True
        
    except Exception as e:
        print(f"✗ CLI integration test failed: {e}")
        return False

def main():
    """Run all validation tests"""
    print("=" * 60)
    print("NetScan Quick Validation")
    print("=" * 60)
    
    # Setup logging
    try:
        from netscan.utils.logging import setup_logging
        setup_logging()
    except:
        pass  # Continue without logging if it fails
    
    tests = [
        ("Import Tests", test_imports),
        ("Database Basic Operations", test_database_basic),
        ("Network Scanner", test_network_scanner),
        ("Configuration Manager", test_config_manager),
        ("Reporting System", test_reporting),
        ("CLI Integration", test_cli_integration),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        print(f"\n[{test_name}]")
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ {test_name} failed with exception: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    print(f"Total Tests: {passed + failed}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {(passed / (passed + failed) * 100):.1f}%")
    
    if failed == 0:
        print("\n🎉 All tests passed! NetScan is ready for use.")
        return 0
    else:
        print(f"\n⚠️  {failed} tests failed. Please check the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 