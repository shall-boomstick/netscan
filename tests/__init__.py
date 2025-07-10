"""
Tests for NetScan application
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add the netscan module to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Test utilities
class TestHelper:
    """Helper class for testing utilities"""
    
    @staticmethod
    def create_test_database():
        """Create a temporary test database"""
        test_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        test_db.close()
        return test_db.name
    
    @staticmethod
    def create_test_config_dir():
        """Create a temporary config directory"""
        return tempfile.mkdtemp(prefix='netscan_test_')
    
    @staticmethod
    def cleanup_test_file(filepath):
        """Clean up test file"""
        if os.path.exists(filepath):
            os.unlink(filepath)
    
    @staticmethod
    def cleanup_test_dir(dirpath):
        """Clean up test directory"""
        if os.path.exists(dirpath):
            shutil.rmtree(dirpath)

# Test data
TEST_HOST_DATA = {
    'ip_address': '192.168.1.100',
    'hostname': 'test-host',
    'ssh_port': 22,
    'status': 'active',
    'os_info': 'Ubuntu 22.04 LTS',
    'kernel_version': '5.4.0-74-generic',
    'uptime': '5 days',
    'cpu_info': 'Intel Core i7',
    'memory_total': 8192,
    'memory_used': 4096,
    'disk_usage': '50%'
}

TEST_SCAN_RESULTS = [
    {
        'ip_address': '192.168.1.100',
        'hostname': 'test-host-1',
        'ssh_port': 22,
        'status': 'active',
        'response_time': 0.5
    },
    {
        'ip_address': '192.168.1.101',
        'hostname': 'test-host-2',
        'ssh_port': 22,
        'status': 'inactive',
        'response_time': 2.0
    },
    {
        'ip_address': '192.168.1.102',
        'hostname': None,
        'ssh_port': 22,
        'status': 'timeout',
        'response_time': 5.0
    }
] 