#!/usr/bin/env python3
"""
Create test data for NetScan database
"""

from netscan.database.operations import db_manager
from datetime import datetime, timedelta
import random

def create_test_data():
    """Create test hosts and scan history"""
    
    # Test host data
    test_hosts = [
        {
            'ip_address': '192.168.1.100',
            'hostname': 'web-server-01',
            'ssh_port': 22,
            'status': 'active',
            'os_info': 'Ubuntu 22.04 LTS',
            'kernel_version': '5.15.0-88-generic',
            'uptime': '15 days, 3 hours, 45 minutes',
            'cpu_info': 'Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz',
            'memory_total': 16384,
            'memory_used': 8192,
            'disk_usage': '{"total": "500GB", "used": "200GB", "free": "300GB"}',
            'working_username': 'admin',
            'auth_method': 'password',
            'auth_attempts': 1
        },
        {
            'ip_address': '192.168.1.101',
            'hostname': 'db-server-01',
            'ssh_port': 22,
            'status': 'active',
            'os_info': 'CentOS 8',
            'kernel_version': '4.18.0-305.el8.x86_64',
            'uptime': '8 days, 12 hours, 30 minutes',
            'cpu_info': 'AMD EPYC 7302P 16-Core Processor',
            'memory_total': 32768,
            'memory_used': 24576,
            'disk_usage': '{"total": "1TB", "used": "600GB", "free": "400GB"}',
            'working_username': 'root',
            'auth_method': 'key',
            'auth_attempts': 2
        },
        {
            'ip_address': '192.168.1.102',
            'hostname': 'app-server-01',
            'ssh_port': 2222,
            'status': 'active',
            'os_info': 'Debian 11',
            'kernel_version': '5.10.0-13-amd64',
            'uptime': '3 days, 7 hours, 15 minutes',
            'cpu_info': 'Intel(R) Xeon(R) E5-2680 v4 @ 2.40GHz',
            'memory_total': 8192,
            'memory_used': 4096,
            'disk_usage': '{"total": "250GB", "used": "150GB", "free": "100GB"}',
            'working_username': 'deploy',
            'auth_method': 'password',
            'auth_attempts': 1
        },
        {
            'ip_address': '192.168.1.103',
            'hostname': 'monitor-01',
            'ssh_port': 22,
            'status': 'inactive',
            'os_info': 'Ubuntu 20.04 LTS',
            'kernel_version': '5.4.0-74-generic',
            'uptime': '45 days, 2 hours, 10 minutes',
            'cpu_info': 'Intel(R) Core(TM) i5-8400 CPU @ 2.80GHz',
            'memory_total': 4096,
            'memory_used': 2048,
            'disk_usage': '{"total": "100GB", "used": "80GB", "free": "20GB"}',
            'working_username': 'monitor',
            'auth_method': 'password',
            'auth_attempts': 3
        },
        {
            'ip_address': '192.168.1.104',
            'hostname': 'backup-01',
            'ssh_port': 22,
            'status': 'error',
            'os_info': 'CentOS 7',
            'kernel_version': '3.10.0-1160.el7.x86_64',
            'uptime': '120 days, 18 hours, 30 minutes',
            'cpu_info': 'Intel(R) Xeon(R) E5-2620 v3 @ 2.40GHz',
            'memory_total': 16384,
            'memory_used': 12288,
            'disk_usage': '{"total": "2TB", "used": "1.8TB", "free": "200GB"}',
            'working_username': None,
            'auth_method': None,
            'auth_attempts': 5
        }
    ]
    
    print("Creating test hosts...")
    for host_data in test_hosts:
        try:
            host = db_manager.create_host(host_data)
            print(f"✓ Created host: {host.ip_address} ({host.hostname})")
        except Exception as e:
            print(f"✗ Error creating host {host_data['ip_address']}: {e}")
    
    # Create scan history
    print("\nCreating scan history...")
    scan_types = ['network', 'auth', 'info', 'full']
    results = ['success', 'partial', 'error']
    
    for host in db_manager.get_all_hosts():
        # Create 2-5 scan history entries per host
        for i in range(random.randint(2, 5)):
            scan_data = {
                'host_id': host.id,
                'scan_type': random.choice(scan_types),
                'result': random.choice(results),
                'scan_duration': random.uniform(0.5, 5.0),
                'timestamp': datetime.utcnow() - timedelta(days=random.randint(0, 30))
            }
            
            if scan_data['result'] == 'error':
                scan_data['error_message'] = 'Connection timeout'
            
            try:
                db_manager.create_scan_history(scan_data)
                print(f"✓ Created scan history for {host.ip_address}")
            except Exception as e:
                print(f"✗ Error creating scan history for {host.ip_address}: {e}")
    
    print("\nTest data creation complete!")
    
    # Show statistics
    stats = db_manager.get_host_statistics()
    print(f"\nDatabase Statistics:")
    print(f"  Total hosts: {stats['total_hosts']}")
    print(f"  Active hosts: {stats['active_hosts']}")
    print(f"  Inactive hosts: {stats['inactive_hosts']}")
    print(f"  Error hosts: {stats['error_hosts']}")

if __name__ == "__main__":
    create_test_data() 