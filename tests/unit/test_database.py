"""
Unit tests for database operations
"""

import pytest
import tempfile
import os
from datetime import datetime
from unittest.mock import Mock, patch

from netscan.database.operations import DatabaseManager
from netscan.database.models import Host, ScanHistory, Config as ConfigModel
from netscan.utils.error_handling import DatabaseError
from tests import TestHelper, TEST_HOST_DATA


class TestDatabaseManager:
    """Test cases for DatabaseManager"""
    
    def setup_method(self):
        """Setup test database for each test"""
        self.test_db_path = TestHelper.create_test_database()
        self.db_manager = DatabaseManager(self.test_db_path)
        self.db_manager.init_database()
    
    def teardown_method(self):
        """Clean up test database after each test"""
        TestHelper.cleanup_test_file(self.test_db_path)
    
    def test_init_database_success(self):
        """Test successful database initialization"""
        assert self.db_manager.engine is not None
        assert self.db_manager.SessionLocal is not None
        assert os.path.exists(self.test_db_path)
    
    def test_init_database_invalid_path(self):
        """Test database initialization with invalid path"""
        invalid_path = "/invalid/path/test.db"
        invalid_db_manager = DatabaseManager(invalid_path)
        
        with pytest.raises(DatabaseError):
            invalid_db_manager.init_database()
    
    def test_get_session(self):
        """Test session creation"""
        session = self.db_manager.get_session()
        assert session is not None
        session.close()
    
    def test_create_host_success(self):
        """Test successful host creation"""
        host = self.db_manager.create_host(TEST_HOST_DATA)
        
        assert host.ip_address == TEST_HOST_DATA['ip_address']
        assert host.hostname == TEST_HOST_DATA['hostname']
        assert host.status == TEST_HOST_DATA['status']
        assert host.id is not None
    
    def test_create_host_duplicate_ip(self):
        """Test creating host with duplicate IP address"""
        # Create first host
        host1 = self.db_manager.create_host(TEST_HOST_DATA)
        
        # Try to create another host with same IP
        updated_data = TEST_HOST_DATA.copy()
        updated_data['hostname'] = 'updated-host'
        
        host2 = self.db_manager.create_host(updated_data)
        
        # Should return updated host, not create new one
        assert host2.ip_address == TEST_HOST_DATA['ip_address']
        assert host2.hostname == 'updated-host'
        assert host2.id == host1.id
    
    def test_get_host_by_ip_found(self):
        """Test getting host by IP address - found"""
        created_host = self.db_manager.create_host(TEST_HOST_DATA)
        
        retrieved_host = self.db_manager.get_host_by_ip(TEST_HOST_DATA['ip_address'])
        
        assert retrieved_host is not None
        assert retrieved_host.ip_address == created_host.ip_address
        assert retrieved_host.id == created_host.id
    
    def test_get_host_by_ip_not_found(self):
        """Test getting host by IP address - not found"""
        host = self.db_manager.get_host_by_ip('192.168.1.999')
        assert host is None
    
    def test_get_all_hosts_empty(self):
        """Test getting all hosts from empty database"""
        hosts = self.db_manager.get_all_hosts()
        assert len(hosts) == 0
    
    def test_get_all_hosts_with_data(self):
        """Test getting all hosts with data"""
        # Create multiple hosts
        host1_data = TEST_HOST_DATA.copy()
        host1_data['ip_address'] = '192.168.1.100'
        
        host2_data = TEST_HOST_DATA.copy()
        host2_data['ip_address'] = '192.168.1.101'
        
        self.db_manager.create_host(host1_data)
        self.db_manager.create_host(host2_data)
        
        hosts = self.db_manager.get_all_hosts()
        assert len(hosts) == 2
        
        ip_addresses = [host.ip_address for host in hosts]
        assert '192.168.1.100' in ip_addresses
        assert '192.168.1.101' in ip_addresses
    
    def test_get_hosts_with_filters(self):
        """Test getting hosts with filters"""
        # Create hosts with different statuses
        active_host = TEST_HOST_DATA.copy()
        active_host['ip_address'] = '192.168.1.100'
        active_host['status'] = 'active'
        
        inactive_host = TEST_HOST_DATA.copy()
        inactive_host['ip_address'] = '192.168.1.101'
        inactive_host['status'] = 'inactive'
        
        self.db_manager.create_host(active_host)
        self.db_manager.create_host(inactive_host)
        
        # Test status filter
        active_hosts = self.db_manager.get_hosts_with_filters(status='active')
        assert len(active_hosts) == 1
        assert active_hosts[0].status == 'active'
        
        # Test OS filter
        ubuntu_hosts = self.db_manager.get_hosts_with_filters(os_info='Ubuntu')
        assert len(ubuntu_hosts) == 2  # Both have Ubuntu in os_info
    
    def test_update_host_by_ip_success(self):
        """Test successful host update by IP"""
        # Create host
        original_host = self.db_manager.create_host(TEST_HOST_DATA)
        
        # Update data
        update_data = {
            'hostname': 'updated-hostname',
            'status': 'inactive',
            'uptime': '10 days'
        }
        
        updated_host = self.db_manager.update_host_by_ip(
            TEST_HOST_DATA['ip_address'], 
            update_data
        )
        
        assert updated_host.hostname == 'updated-hostname'
        assert updated_host.status == 'inactive'
        assert updated_host.uptime == '10 days'
        assert updated_host.id == original_host.id
    
    def test_update_host_by_ip_not_found(self):
        """Test updating non-existent host"""
        update_data = {'hostname': 'new-hostname'}
        
        updated_host = self.db_manager.update_host_by_ip(
            '192.168.1.999', 
            update_data
        )
        
        assert updated_host is None
    
    def test_delete_host_success(self):
        """Test successful host deletion"""
        # Create host
        host = self.db_manager.create_host(TEST_HOST_DATA)
        
        # Delete host
        result = self.db_manager.delete_host(host.id)
        assert result is True
        
        # Verify deletion
        deleted_host = self.db_manager.get_host_by_ip(TEST_HOST_DATA['ip_address'])
        assert deleted_host is None
    
    def test_delete_host_not_found(self):
        """Test deleting non-existent host"""
        result = self.db_manager.delete_host(999)
        assert result is False
    
    def test_create_scan_history(self):
        """Test creating scan history record"""
        # Create host first
        host = self.db_manager.create_host(TEST_HOST_DATA)
        
        # Create scan history
        scan_data = {
            'host_id': host.id,
            'scan_type': 'network',
            'result': 'success',
            'scan_duration': 2.5
        }
        
        scan_history = self.db_manager.create_scan_history(scan_data)
        
        assert scan_history.host_id == host.id
        assert scan_history.scan_type == 'network'
        assert scan_history.result == 'success'
        assert scan_history.scan_duration == 2.5
        assert scan_history.id is not None
    
    def test_get_scan_history_for_host(self):
        """Test getting scan history for a specific host"""
        # Create host
        host = self.db_manager.create_host(TEST_HOST_DATA)
        
        # Create multiple scan history records
        scan1 = {
            'host_id': host.id,
            'scan_type': 'network',
            'result': 'success',
            'scan_duration': 1.0
        }
        
        scan2 = {
            'host_id': host.id,
            'scan_type': 'info',
            'result': 'success',
            'scan_duration': 2.0
        }
        
        self.db_manager.create_scan_history(scan1)
        self.db_manager.create_scan_history(scan2)
        
        # Get scan history
        history = self.db_manager.get_scan_history_for_host(host.id)
        
        assert len(history) == 2
        scan_types = [scan.scan_type for scan in history]
        assert 'network' in scan_types
        assert 'info' in scan_types
    
    def test_get_scan_history_with_filters(self):
        """Test getting scan history with filters"""
        # Create host
        host = self.db_manager.create_host(TEST_HOST_DATA)
        
        # Create scan history with different types
        network_scan = {
            'host_id': host.id,
            'scan_type': 'network',
            'result': 'success',
            'scan_duration': 1.0
        }
        
        info_scan = {
            'host_id': host.id,
            'scan_type': 'info',
            'result': 'success',
            'scan_duration': 2.0
        }
        
        self.db_manager.create_scan_history(network_scan)
        self.db_manager.create_scan_history(info_scan)
        
        # Test filter by scan type
        network_history = self.db_manager.get_scan_history_with_filters(
            scan_type='network'
        )
        
        assert len(network_history) == 1
        assert network_history[0].scan_type == 'network'
    
    def test_get_config_not_found(self):
        """Test getting non-existent configuration"""
        value = self.db_manager.get_config('nonexistent_key')
        assert value is None
    
    def test_set_and_get_config(self):
        """Test setting and getting configuration"""
        key = 'test_key'
        value = 'test_value'
        
        # Set config
        self.db_manager.set_config(key, value)
        
        # Get config
        retrieved_value = self.db_manager.get_config(key)
        assert retrieved_value == value
    
    def test_set_config_update_existing(self):
        """Test updating existing configuration"""
        key = 'test_key'
        original_value = 'original_value'
        updated_value = 'updated_value'
        
        # Set original value
        self.db_manager.set_config(key, original_value)
        
        # Update value
        self.db_manager.set_config(key, updated_value)
        
        # Verify update
        retrieved_value = self.db_manager.get_config(key)
        assert retrieved_value == updated_value
    
    def test_delete_config(self):
        """Test deleting configuration"""
        key = 'test_key'
        value = 'test_value'
        
        # Set config
        self.db_manager.set_config(key, value)
        
        # Delete config
        result = self.db_manager.delete_config(key)
        assert result is True
        
        # Verify deletion
        retrieved_value = self.db_manager.get_config(key)
        assert retrieved_value is None
    
    def test_delete_config_not_found(self):
        """Test deleting non-existent configuration"""
        result = self.db_manager.delete_config('nonexistent_key')
        assert result is False
    
    def test_get_database_stats(self):
        """Test getting database statistics"""
        # Create some test data
        host1_data = TEST_HOST_DATA.copy()
        host1_data['ip_address'] = '192.168.1.100'
        host1_data['status'] = 'active'
        
        host2_data = TEST_HOST_DATA.copy()
        host2_data['ip_address'] = '192.168.1.101'
        host2_data['status'] = 'inactive'
        
        host1 = self.db_manager.create_host(host1_data)
        host2 = self.db_manager.create_host(host2_data)
        
        # Create scan history
        scan_data = {
            'host_id': host1.id,
            'scan_type': 'network',
            'result': 'success',
            'scan_duration': 1.0
        }
        self.db_manager.create_scan_history(scan_data)
        
        # Get stats
        stats = self.db_manager.get_database_stats()
        
        assert stats['total_hosts'] == 2
        assert stats['active_hosts'] == 1
        assert stats['inactive_hosts'] == 1
        assert stats['total_scans'] == 1
        assert 'last_scan' in stats
    
    @patch('netscan.database.operations.DatabaseManager.get_session')
    def test_database_error_handling(self, mock_get_session):
        """Test database error handling"""
        # Mock session to raise an exception
        mock_session = Mock()
        mock_session.rollback.return_value = None
        mock_session.__enter__.return_value = mock_session
        mock_session.__exit__.return_value = None
        mock_session.add.side_effect = Exception("Database error")
        
        mock_get_session.return_value = mock_session
        
        # This should handle the error gracefully
        with pytest.raises(DatabaseError):
            self.db_manager.create_host(TEST_HOST_DATA)
        
        # Verify rollback was called
        mock_session.rollback.assert_called_once()


class TestDatabaseModels:
    """Test cases for database models"""
    
    def test_host_model_creation(self):
        """Test Host model creation"""
        host = Host(**TEST_HOST_DATA)
        
        assert host.ip_address == TEST_HOST_DATA['ip_address']
        assert host.hostname == TEST_HOST_DATA['hostname']
        assert host.ssh_port == TEST_HOST_DATA['ssh_port']
        assert host.status == TEST_HOST_DATA['status']
    
    def test_host_model_to_dict(self):
        """Test Host model to_dict method"""
        host = Host(**TEST_HOST_DATA)
        host.id = 1
        host.created_at = datetime.now()
        host.last_scan = datetime.now()
        
        host_dict = host.to_dict()
        
        assert host_dict['id'] == 1
        assert host_dict['ip_address'] == TEST_HOST_DATA['ip_address']
        assert host_dict['hostname'] == TEST_HOST_DATA['hostname']
        assert 'created_at' in host_dict
        assert 'last_scan' in host_dict
    
    def test_scan_history_model_creation(self):
        """Test ScanHistory model creation"""
        scan_data = {
            'host_id': 1,
            'scan_type': 'network',
            'result': 'success',
            'scan_duration': 2.5
        }
        
        scan = ScanHistory(**scan_data)
        
        assert scan.host_id == 1
        assert scan.scan_type == 'network'
        assert scan.result == 'success'
        assert scan.scan_duration == 2.5
    
    def test_scan_history_model_to_dict(self):
        """Test ScanHistory model to_dict method"""
        scan_data = {
            'host_id': 1,
            'scan_type': 'network',
            'result': 'success',
            'scan_duration': 2.5
        }
        
        scan = ScanHistory(**scan_data)
        scan.id = 1
        scan.timestamp = datetime.now()
        
        scan_dict = scan.to_dict()
        
        assert scan_dict['id'] == 1
        assert scan_dict['host_id'] == 1
        assert scan_dict['scan_type'] == 'network'
        assert 'timestamp' in scan_dict
    
    def test_config_model_creation(self):
        """Test Config model creation"""
        config_data = {
            'key': 'test_key',
            'value': 'test_value'
        }
        
        config = ConfigModel(**config_data)
        
        assert config.key == 'test_key'
        assert config.value == 'test_value'
    
    def test_config_model_to_dict(self):
        """Test Config model to_dict method"""
        config_data = {
            'key': 'test_key',
            'value': 'test_value'
        }
        
        config = ConfigModel(**config_data)
        config.created_at = datetime.now()
        
        config_dict = config.to_dict()
        
        assert config_dict['key'] == 'test_key'
        assert config_dict['value'] == 'test_value'
        assert 'created_at' in config_dict 