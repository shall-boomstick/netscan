"""
System information collector for NetScan

This module collects system information from remote hosts via SSH.
"""

import json
import re
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from .ssh import SSHConnector
from ..utils.logging import get_logger

console = Console()
logger = get_logger()


class SystemInfoCollector:
    """System information collector class"""
    
    def __init__(self, ssh_connector: SSHConnector):
        self.ssh_connector = ssh_connector
        
        # Define system information commands
        self.commands = {
            'os_info': 'uname -a',
            'kernel_version': 'uname -r',
            'hostname': 'hostname -f',
            'uptime': 'uptime',
            'cpu_info': 'cat /proc/cpuinfo',
            'memory_info': 'free -m',
            'disk_usage': 'df -h',
            'network_interfaces': 'ip addr show',
            'processes': 'ps aux | head -20',
            'system_load': 'cat /proc/loadavg',
            'disk_info': 'lsblk -f',
            'users': 'who',
            'timezone': 'timedatectl | grep "Time zone" || date +%Z',
            'distribution': 'cat /etc/os-release || cat /etc/redhat-release || cat /etc/debian_version'
        }
    
    def parse_memory_info(self, memory_output: str) -> Dict[str, Any]:
        """Parse memory information from free command output"""
        memory_info = {
            'total_mb': 0,
            'used_mb': 0,
            'free_mb': 0,
            'available_mb': 0,
            'usage_percent': 0.0
        }
        
        try:
            lines = memory_output.strip().split('\n')
            for line in lines:
                if line.startswith('Mem:'):
                    parts = line.split()
                    if len(parts) >= 4:
                        memory_info['total_mb'] = int(parts[1])
                        memory_info['used_mb'] = int(parts[2])
                        memory_info['free_mb'] = int(parts[3])
                        if len(parts) >= 7:
                            memory_info['available_mb'] = int(parts[6])
                        
                        # Calculate usage percentage
                        if memory_info['total_mb'] > 0:
                            memory_info['usage_percent'] = (memory_info['used_mb'] / memory_info['total_mb']) * 100
                    break
        except Exception as e:
            logger.error(f"Error parsing memory info: {e}")
        
        return memory_info
    
    def parse_cpu_info(self, cpu_output: str) -> Dict[str, Any]:
        """Parse CPU information from /proc/cpuinfo"""
        cpu_info = {
            'model': 'Unknown',
            'cores': 0,
            'threads': 0,
            'architecture': 'Unknown',
            'vendor': 'Unknown',
            'frequency': 'Unknown'
        }
        
        try:
            processors = 0
            model_name = None
            
            lines = cpu_output.strip().split('\n')
            for line in lines:
                if line.startswith('processor'):
                    processors += 1
                elif line.startswith('model name'):
                    if not model_name:
                        model_name = line.split(':', 1)[1].strip()
                elif line.startswith('vendor_id'):
                    cpu_info['vendor'] = line.split(':', 1)[1].strip()
                elif line.startswith('cpu MHz'):
                    cpu_info['frequency'] = f"{line.split(':', 1)[1].strip()} MHz"
            
            cpu_info['threads'] = processors
            cpu_info['cores'] = processors  # Simplified - actual cores may be different
            if model_name:
                cpu_info['model'] = model_name
            
        except Exception as e:
            logger.error(f"Error parsing CPU info: {e}")
        
        return cpu_info
    
    def parse_disk_usage(self, disk_output: str) -> List[Dict[str, Any]]:
        """Parse disk usage information from df command"""
        disk_info = []
        
        try:
            lines = disk_output.strip().split('\n')
            for i, line in enumerate(lines):
                if i == 0:  # Skip header
                    continue
                
                parts = line.split()
                if len(parts) >= 6:
                    disk_info.append({
                        'filesystem': parts[0],
                        'size': parts[1],
                        'used': parts[2],
                        'available': parts[3],
                        'use_percent': parts[4],
                        'mounted_on': parts[5]
                    })
        except Exception as e:
            logger.error(f"Error parsing disk usage: {e}")
        
        return disk_info
    
    def parse_uptime(self, uptime_output: str) -> Dict[str, Any]:
        """Parse system uptime information"""
        uptime_info = {
            'raw': uptime_output.strip(),
            'uptime_days': 0,
            'uptime_hours': 0,
            'uptime_minutes': 0,
            'load_average': []
        }
        
        try:
            # Extract uptime
            uptime_match = re.search(r'up\s+(?:(\d+)\s+days?,\s*)?(?:(\d+):(\d+)|(\d+)\s+min)', uptime_output)
            if uptime_match:
                days = int(uptime_match.group(1) or 0)
                hours = int(uptime_match.group(2) or 0)
                minutes = int(uptime_match.group(3) or uptime_match.group(4) or 0)
                
                uptime_info['uptime_days'] = days
                uptime_info['uptime_hours'] = hours
                uptime_info['uptime_minutes'] = minutes
            
            # Extract load averages
            load_match = re.search(r'load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)', uptime_output)
            if load_match:
                uptime_info['load_average'] = [
                    float(load_match.group(1)),
                    float(load_match.group(2)),
                    float(load_match.group(3))
                ]
        except Exception as e:
            logger.error(f"Error parsing uptime: {e}")
        
        return uptime_info
    
    def parse_distribution_info(self, dist_output: str) -> Dict[str, Any]:
        """Parse Linux distribution information"""
        dist_info = {
            'name': 'Unknown',
            'version': 'Unknown',
            'codename': 'Unknown',
            'id': 'Unknown'
        }
        
        try:
            lines = dist_output.strip().split('\n')
            for line in lines:
                if '=' in line:
                    key, value = line.split('=', 1)
                    value = value.strip('"')
                    
                    if key == 'NAME':
                        dist_info['name'] = value
                    elif key == 'VERSION':
                        dist_info['version'] = value
                    elif key == 'VERSION_CODENAME':
                        dist_info['codename'] = value
                    elif key == 'ID':
                        dist_info['id'] = value
                elif line.strip():
                    # Handle single-line formats (RedHat, Debian)
                    dist_info['name'] = line.strip()
        except Exception as e:
            logger.error(f"Error parsing distribution info: {e}")
        
        return dist_info
    
    def collect_system_info(self, host: str, port: int = 22, username: str = None, 
                           password: str = None, key_file: str = None) -> Dict[str, Any]:
        """Collect comprehensive system information from a host"""
        
        info = {
            'host': host,
            'port': port,
            'username': username,
            'collection_success': False,
            'collection_errors': [],
            'raw_outputs': {},
            'parsed_info': {}
        }
        
        console.print(f"[blue]Collecting system information from {host}...[/blue]")
        
        # Execute all commands
        for info_type, command in self.commands.items():
            try:
                result = self.ssh_connector.execute_command(
                    host, command, port, username, password, key_file
                )
                
                if result['success']:
                    info['raw_outputs'][info_type] = result['stdout']
                    logger.info(f"Successfully collected {info_type} from {host}")
                else:
                    error_msg = f"Failed to collect {info_type}: {result['error']}"
                    info['collection_errors'].append(error_msg)
                    logger.warning(error_msg)
                    
            except Exception as e:
                error_msg = f"Error collecting {info_type}: {str(e)}"
                info['collection_errors'].append(error_msg)
                logger.error(error_msg)
        
        # Parse collected information
        try:
            raw = info['raw_outputs']
            parsed = {}
            
            # Basic system info
            parsed['os_info'] = raw.get('os_info', 'Unknown')
            parsed['kernel_version'] = raw.get('kernel_version', 'Unknown')
            parsed['hostname'] = raw.get('hostname', host)
            
            # Parse complex information
            if 'memory_info' in raw:
                parsed['memory'] = self.parse_memory_info(raw['memory_info'])
            
            if 'cpu_info' in raw:
                parsed['cpu'] = self.parse_cpu_info(raw['cpu_info'])
            
            if 'disk_usage' in raw:
                parsed['disk'] = self.parse_disk_usage(raw['disk_usage'])
            
            if 'uptime' in raw:
                parsed['uptime'] = self.parse_uptime(raw['uptime'])
            
            if 'distribution' in raw:
                parsed['distribution'] = self.parse_distribution_info(raw['distribution'])
            
            # Additional info
            parsed['system_load'] = raw.get('system_load', 'Unknown')
            parsed['users'] = raw.get('users', 'Unknown')
            parsed['timezone'] = raw.get('timezone', 'Unknown')
            
            info['parsed_info'] = parsed
            info['collection_success'] = len(info['collection_errors']) == 0
            
        except Exception as e:
            error_msg = f"Error parsing collected information: {str(e)}"
            info['collection_errors'].append(error_msg)
            logger.error(error_msg)
        
        return info
    
    def collect_from_multiple_hosts(self, hosts: List[str], port: int = 22, 
                                   username: str = None, password: str = None, 
                                   key_file: str = None) -> List[Dict[str, Any]]:
        """Collect system information from multiple hosts"""
        
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
            transient=True
        ) as progress:
            
            task = progress.add_task(f"Collecting system info from {len(hosts)} hosts", total=len(hosts))
            
            for host in hosts:
                try:
                    info = self.collect_system_info(host, port, username, password, key_file)
                    results.append(info)
                    
                    if info['collection_success']:
                        console.print(f"[green]✓ System info collected from {host}[/green]")
                    else:
                        console.print(f"[yellow]⚠ Partial info collected from {host} ({len(info['collection_errors'])} errors)[/yellow]")
                    
                    progress.update(task, advance=1)
                    
                except Exception as e:
                    error_info = {
                        'host': host,
                        'collection_success': False,
                        'collection_errors': [f"Failed to collect info: {str(e)}"],
                        'raw_outputs': {},
                        'parsed_info': {}
                    }
                    results.append(error_info)
                    console.print(f"[red]✗ Failed to collect info from {host}: {e}[/red]")
                    progress.update(task, advance=1)
        
        return results
    
    def collect_from_multiple_hosts_with_credentials(self, hosts: List[str], port: int = 22, 
                                                   credentials: List[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """Collect system information from multiple hosts using multiple credentials"""
        
        results = []
        
        if not credentials:
            return [{'host': host, 'collection_success': False, 'collection_errors': ['No credentials provided']} for host in hosts]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
            transient=True
        ) as progress:
            
            task = progress.add_task(f"Collecting system info from {len(hosts)} hosts", total=len(hosts))
            
            for host in hosts:
                try:
                    # Try to find working credentials for this host
                    working_creds = None
                    auth_result = self.ssh_connector.try_multiple_credentials(host, port, credentials)
                    
                    if auth_result['connected']:
                        # Extract working credentials
                        successful_cred = auth_result.get('successful_credential', {})
                        working_creds = {
                            'username': successful_cred.get('username'),
                            'password': None,
                            'key_file': None
                        }
                        
                        # Determine authentication method
                        method = successful_cred.get('method', '')
                        if method == 'password':
                            # Find the password from the credentials list
                            for cred in credentials:
                                if cred.get('username') == working_creds['username'] and cred.get('password'):
                                    working_creds['password'] = cred['password']
                                    break
                        elif method.startswith('key:'):
                            working_creds['key_file'] = method.split(':', 1)[1]
                        
                        # Collect system information using working credentials
                        info = self.collect_system_info(
                            host, port, 
                            working_creds['username'], 
                            working_creds['password'], 
                            working_creds['key_file']
                        )
                        
                        # Add authentication info to results
                        info['successful_credential'] = successful_cred
                        info['auth_attempts'] = len(auth_result.get('attempts', []))
                        
                        results.append(info)
                        
                        if info['collection_success']:
                            console.print(f"[green]✓ System info collected from {host} using {working_creds['username']}[/green]")
                        else:
                            console.print(f"[yellow]⚠ Partial info collected from {host} ({len(info['collection_errors'])} errors)[/yellow]")
                    else:
                        # No working credentials found
                        error_info = {
                            'host': host,
                            'collection_success': False,
                            'collection_errors': [f"Authentication failed: {auth_result['error']}"],
                            'raw_outputs': {},
                            'parsed_info': {},
                            'auth_attempts': len(auth_result.get('attempts', []))
                        }
                        results.append(error_info)
                        console.print(f"[red]✗ Failed to authenticate to {host} with any credentials[/red]")
                    
                    progress.update(task, advance=1)
                    
                except Exception as e:
                    error_info = {
                        'host': host,
                        'collection_success': False,
                        'collection_errors': [f"Failed to collect info: {str(e)}"],
                        'raw_outputs': {},
                        'parsed_info': {},
                        'auth_attempts': 0
                    }
                    results.append(error_info)
                    console.print(f"[red]✗ Failed to collect info from {host}: {e}[/red]")
                    progress.update(task, advance=1)
        
        return results
    
    def format_system_info(self, info: Dict[str, Any]) -> str:
        """Format system information for display"""
        if not info['collection_success']:
            return f"Failed to collect system information from {info['host']}"
        
        parsed = info['parsed_info']
        output = []
        
        output.append(f"System Information for {info['host']}")
        output.append("=" * 50)
        
        # Basic info
        output.append(f"Hostname: {parsed.get('hostname', 'Unknown')}")
        output.append(f"OS: {parsed.get('os_info', 'Unknown')}")
        output.append(f"Kernel: {parsed.get('kernel_version', 'Unknown')}")
        
        # Distribution
        if 'distribution' in parsed:
            dist = parsed['distribution']
            output.append(f"Distribution: {dist['name']} {dist['version']}")
        
        # CPU
        if 'cpu' in parsed:
            cpu = parsed['cpu']
            output.append(f"CPU: {cpu['model']} ({cpu['threads']} threads)")
        
        # Memory
        if 'memory' in parsed:
            mem = parsed['memory']
            output.append(f"Memory: {mem['used_mb']}MB / {mem['total_mb']}MB ({mem['usage_percent']:.1f}% used)")
        
        # Uptime
        if 'uptime' in parsed:
            uptime = parsed['uptime']
            output.append(f"Uptime: {uptime['uptime_days']}d {uptime['uptime_hours']}h {uptime['uptime_minutes']}m")
        
        # Load average
        if 'uptime' in parsed and parsed['uptime']['load_average']:
            load = parsed['uptime']['load_average']
            output.append(f"Load Average: {load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}")
        
        return "\n".join(output) 