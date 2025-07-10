"""
Data export functionality for NetScan reports

This module handles exporting report data to various file formats.
"""

import json
import csv
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
from datetime import datetime
import sqlite3

from ..database.models import Host, ScanHistory
from ..utils.logging import get_logger

logger = get_logger()


class ReportExporter:
    """Report exporter class for various file formats"""
    
    def __init__(self):
        self.supported_formats = ['json', 'csv', 'xml', 'txt', 'sql']
    
    def export_hosts_json(self, hosts: List[Host], filepath: str = None) -> Union[bool, str]:
        """Export hosts to JSON file or return JSON string"""
        try:
            hosts_data = []
            for host in hosts:
                host_dict = host.to_dict()
                hosts_data.append(host_dict)
            
            export_data = {
                'metadata': {
                    'export_time': datetime.now().isoformat(),
                    'total_hosts': len(hosts),
                    'format': 'json',
                    'source': 'netscan'
                },
                'hosts': hosts_data
            }
            
            json_string = json.dumps(export_data, indent=2, default=str)
            
            # If filepath is provided, write to file
            if filepath:
                with open(filepath, 'w') as f:
                    f.write(json_string)
                
                logger.info(f"Exported {len(hosts)} hosts to JSON: {filepath}")
                return True
            else:
                # Return JSON string
                return json_string
            
        except Exception as e:
            logger.error(f"Error exporting to JSON: {e}")
            return False if filepath else "{}"
    
    def export_hosts_csv(self, hosts: List[Host], filepath: str) -> bool:
        """Export hosts to CSV file"""
        try:
            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    'IP_Address', 'Hostname', 'SSH_Port', 'Status', 'OS_Info',
                    'Kernel_Version', 'Uptime', 'CPU_Info', 'Memory_Total_MB',
                    'Memory_Used_MB', 'Memory_Usage_Percent', 'Disk_Usage',
                    'Last_Scan', 'Created_At'
                ])
                
                # Write data
                for host in hosts:
                    memory_usage_pct = ""
                    if host.memory_total and host.memory_used:
                        memory_usage_pct = f"{(host.memory_used / host.memory_total) * 100:.1f}"
                    
                    writer.writerow([
                        host.ip_address,
                        host.hostname or '',
                        host.ssh_port,
                        host.status,
                        host.os_info or '',
                        host.kernel_version or '',
                        host.uptime or '',
                        host.cpu_info or '',
                        host.memory_total or '',
                        host.memory_used or '',
                        memory_usage_pct,
                        host.disk_usage or '',
                        host.last_scan.isoformat() if host.last_scan else '',
                        host.created_at.isoformat() if host.created_at else ''
                    ])
            
            logger.info(f"Exported {len(hosts)} hosts to CSV: {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")
            return False
    
    def export_hosts_xml(self, hosts: List[Host], filepath: str) -> bool:
        """Export hosts to XML file"""
        try:
            root = ET.Element('netscan_report')
            
            # Add metadata
            metadata = ET.SubElement(root, 'metadata')
            ET.SubElement(metadata, 'export_time').text = datetime.now().isoformat()
            ET.SubElement(metadata, 'total_hosts').text = str(len(hosts))
            ET.SubElement(metadata, 'format').text = 'xml'
            ET.SubElement(metadata, 'source').text = 'netscan'
            
            # Add hosts
            hosts_element = ET.SubElement(root, 'hosts')
            
            for host in hosts:
                host_element = ET.SubElement(hosts_element, 'host')
                
                # Add host attributes
                host_element.set('id', str(host.id))
                
                # Add host data
                ET.SubElement(host_element, 'ip_address').text = host.ip_address
                ET.SubElement(host_element, 'hostname').text = host.hostname or ''
                ET.SubElement(host_element, 'ssh_port').text = str(host.ssh_port)
                ET.SubElement(host_element, 'status').text = host.status
                ET.SubElement(host_element, 'os_info').text = host.os_info or ''
                ET.SubElement(host_element, 'kernel_version').text = host.kernel_version or ''
                ET.SubElement(host_element, 'uptime').text = host.uptime or ''
                ET.SubElement(host_element, 'cpu_info').text = host.cpu_info or ''
                ET.SubElement(host_element, 'memory_total').text = str(host.memory_total or '')
                ET.SubElement(host_element, 'memory_used').text = str(host.memory_used or '')
                ET.SubElement(host_element, 'disk_usage').text = host.disk_usage or ''
                ET.SubElement(host_element, 'last_scan').text = host.last_scan.isoformat() if host.last_scan else ''
                ET.SubElement(host_element, 'created_at').text = host.created_at.isoformat() if host.created_at else ''
            
            # Write to file
            tree = ET.ElementTree(root)
            tree.write(filepath, encoding='utf-8', xml_declaration=True)
            
            logger.info(f"Exported {len(hosts)} hosts to XML: {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to XML: {e}")
            return False
    
    def export_hosts_text(self, hosts: List[Host], filepath: str, include_summary: bool = True) -> bool:
        """Export hosts to plain text file"""
        try:
            with open(filepath, 'w') as f:
                f.write("NetScan Host Report\n")
                f.write("=" * 60 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total hosts: {len(hosts)}\n\n")
                
                # Summary statistics
                if include_summary:
                    active_hosts = len([h for h in hosts if h.status == 'active'])
                    inactive_hosts = len([h for h in hosts if h.status == 'inactive'])
                    error_hosts = len([h for h in hosts if h.status == 'error'])
                    
                    f.write("SUMMARY STATISTICS\n")
                    f.write("-" * 30 + "\n")
                    f.write(f"Active hosts: {active_hosts}\n")
                    f.write(f"Inactive hosts: {inactive_hosts}\n")
                    f.write(f"Error hosts: {error_hosts}\n")
                    
                    if len(hosts) > 0:
                        success_rate = (active_hosts / len(hosts)) * 100
                        f.write(f"Success rate: {success_rate:.1f}%\n")
                    f.write("\n")
                
                # Host details
                f.write("HOST DETAILS\n")
                f.write("-" * 30 + "\n\n")
                
                for i, host in enumerate(hosts, 1):
                    f.write(f"Host #{i}: {host.ip_address}\n")
                    f.write("-" * 40 + "\n")
                    f.write(f"  Hostname: {host.hostname or 'Unknown'}\n")
                    f.write(f"  SSH Port: {host.ssh_port}\n")
                    f.write(f"  Status: {host.status}\n")
                    f.write(f"  OS Info: {host.os_info or 'Unknown'}\n")
                    f.write(f"  Kernel: {host.kernel_version or 'Unknown'}\n")
                    f.write(f"  Uptime: {host.uptime or 'Unknown'}\n")
                    f.write(f"  CPU: {host.cpu_info or 'Unknown'}\n")
                    
                    if host.memory_total and host.memory_used:
                        usage_pct = (host.memory_used / host.memory_total) * 100
                        f.write(f"  Memory: {host.memory_used}MB/{host.memory_total}MB ({usage_pct:.1f}%)\n")
                    else:
                        f.write(f"  Memory: Unknown\n")
                    
                    f.write(f"  Disk Usage: {host.disk_usage or 'Unknown'}\n")
                    f.write(f"  Last Scan: {host.last_scan.strftime('%Y-%m-%d %H:%M:%S') if host.last_scan else 'Never'}\n")
                    f.write(f"  Created: {host.created_at.strftime('%Y-%m-%d %H:%M:%S') if host.created_at else 'Unknown'}\n")
                    f.write("\n")
            
            logger.info(f"Exported {len(hosts)} hosts to text: {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to text: {e}")
            return False
    
    def export_hosts_sql(self, hosts: List[Host], filepath: str, table_name: str = 'netscan_hosts') -> bool:
        """Export hosts as SQL INSERT statements"""
        try:
            with open(filepath, 'w') as f:
                f.write(f"-- NetScan Host Export\n")
                f.write(f"-- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"-- Total hosts: {len(hosts)}\n\n")
                
                # Create table statement
                f.write(f"CREATE TABLE IF NOT EXISTS {table_name} (\n")
                f.write("    id INTEGER PRIMARY KEY,\n")
                f.write("    ip_address TEXT NOT NULL,\n")
                f.write("    hostname TEXT,\n")
                f.write("    ssh_port INTEGER,\n")
                f.write("    status TEXT,\n")
                f.write("    os_info TEXT,\n")
                f.write("    kernel_version TEXT,\n")
                f.write("    uptime TEXT,\n")
                f.write("    cpu_info TEXT,\n")
                f.write("    memory_total INTEGER,\n")
                f.write("    memory_used INTEGER,\n")
                f.write("    disk_usage TEXT,\n")
                f.write("    last_scan TIMESTAMP,\n")
                f.write("    created_at TIMESTAMP\n")
                f.write(");\n\n")
                
                # Insert statements
                for host in hosts:
                    values = [
                        str(host.id),
                        f"'{host.ip_address}'",
                        f"'{host.hostname}'" if host.hostname else "NULL",
                        str(host.ssh_port),
                        f"'{host.status}'",
                        f"'{host.os_info}'" if host.os_info else "NULL",
                        f"'{host.kernel_version}'" if host.kernel_version else "NULL",
                        f"'{host.uptime}'" if host.uptime else "NULL",
                        f"'{host.cpu_info}'" if host.cpu_info else "NULL",
                        str(host.memory_total) if host.memory_total else "NULL",
                        str(host.memory_used) if host.memory_used else "NULL",
                        f"'{host.disk_usage}'" if host.disk_usage else "NULL",
                        f"'{host.last_scan.isoformat()}'" if host.last_scan else "NULL",
                        f"'{host.created_at.isoformat()}'" if host.created_at else "NULL"
                    ]
                    
                    f.write(f"INSERT INTO {table_name} VALUES ({', '.join(values)});\n")
            
            logger.info(f"Exported {len(hosts)} hosts to SQL: {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to SQL: {e}")
            return False
    
    def export_scan_history(self, scan_history: List[ScanHistory], filepath: str, format: str = 'json') -> bool:
        """Export scan history to file"""
        try:
            if format.lower() == 'json':
                history_data = []
                for scan in scan_history:
                    history_data.append(scan.to_dict())
                
                export_data = {
                    'metadata': {
                        'export_time': datetime.now().isoformat(),
                        'total_scans': len(scan_history),
                        'format': 'json',
                        'type': 'scan_history'
                    },
                    'scan_history': history_data
                }
                
                with open(filepath, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
            
            elif format.lower() == 'csv':
                with open(filepath, 'w', newline='') as f:
                    writer = csv.writer(f)
                    
                    # Write header
                    writer.writerow([
                        'ID', 'Host_ID', 'Scan_Type', 'Result', 'Error_Message',
                        'Scan_Duration', 'Timestamp'
                    ])
                    
                    # Write data
                    for scan in scan_history:
                        writer.writerow([
                            scan.id,
                            scan.host_id,
                            scan.scan_type or '',
                            scan.result or '',
                            scan.error_message or '',
                            scan.scan_duration or '',
                            scan.timestamp.isoformat() if scan.timestamp else ''
                        ])
            
            logger.info(f"Exported {len(scan_history)} scan history records to {format.upper()}: {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting scan history: {e}")
            return False
    
    def get_export_filename(self, base_name: str, format: str, timestamp: bool = True) -> str:
        """Generate export filename with timestamp"""
        if timestamp:
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            return f"{base_name}_{timestamp_str}.{format.lower()}"
        else:
            return f"{base_name}.{format.lower()}" 