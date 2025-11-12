"""
SSH connection handler for NetScan

This module handles SSH connections and authentication using Paramiko.
"""

import paramiko
import socket
import time
from typing import Optional, Dict, Any, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from pathlib import Path
import os

from ..utils.logging import get_logger

console = Console()
logger = get_logger()


class SSHConnector:
    """SSH connection handler class"""
    
    def __init__(self, timeout: int = 5, max_retries: int = 3):
        self.timeout = timeout
        self.max_retries = max_retries
        self.connection_pool = {}
    
    def create_ssh_client(self) -> paramiko.SSHClient:
        """Create and configure SSH client"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return client
    
    def test_connection(self, host: str, port: int = 22, username: str = None, 
                       password: str = None, key_file: str = None) -> Dict[str, Any]:
        """Test SSH connection to a host"""
        
        result = {
            'host': host,
            'port': port,
            'username': username,
            'connected': False,
            'error': None,
            'auth_method': None,
            'server_info': None,
            'connection_time': None
        }
        
        start_time = time.time()
        client = None
        
        try:
            client = self.create_ssh_client()
            
            # Try connection
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                key_filename=key_file,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False if not key_file else True
            )
            
            result['connected'] = True
            result['auth_method'] = 'key' if key_file else 'password'
            result['connection_time'] = time.time() - start_time
            
            # Get server information
            try:
                transport = client.get_transport()
                if transport:
                    server_version = transport.remote_version
                    result['server_info'] = server_version
            except Exception as e:
                logger.debug(f"Could not get server info for {host}: {e}")
            
            logger.info(f"SSH connection successful: {username}@{host}:{port}")
            
        except paramiko.AuthenticationException as e:
            result['error'] = f"Authentication failed: {str(e)}"
            logger.warning(f"SSH authentication failed: {username}@{host}:{port}")
        except paramiko.SSHException as e:
            result['error'] = f"SSH error: {str(e)}"
        except socket.timeout:
            result['error'] = "Connection timeout"
        except socket.error as e:
            result['error'] = f"Network error: {str(e)}"
        except Exception as e:
            result['error'] = f"Unexpected error: {str(e)}"
            logger.error(f"SSH connection to {host}: {str(e)}")
        
        finally:
            if client:
                try:
                    client.close()
                except:
                    pass
        
        return result
    
    def execute_command(self, host: str, command: str, port: int = 22, 
                       username: str = None, password: str = None, 
                       key_file: str = None) -> Dict[str, Any]:
        """Execute command on remote host via SSH"""
        
        result = {
            'host': host,
            'command': command,
            'success': False,
            'stdout': '',
            'stderr': '',
            'exit_code': None,
            'execution_time': None,
            'error': None
        }
        
        start_time = time.time()
        client = None
        
        try:
            client = self.create_ssh_client()
            
            # Connect
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                key_filename=key_file,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False if not key_file else True
            )
            
            # Execute command
            stdin, stdout, stderr = client.exec_command(command, timeout=self.timeout)
            
            # Get results
            result['stdout'] = stdout.read().decode('utf-8').strip()
            result['stderr'] = stderr.read().decode('utf-8').strip()
            result['exit_code'] = stdout.channel.recv_exit_status()
            result['execution_time'] = time.time() - start_time
            result['success'] = result['exit_code'] == 0
            
            logger.info(f"Command executed on {host}: {command} (exit_code: {result['exit_code']})")
            
        except paramiko.AuthenticationException as e:
            result['error'] = f"Authentication failed: {str(e)}"
        except paramiko.SSHException as e:
            result['error'] = f"SSH error: {str(e)}"
        except socket.timeout:
            result['error'] = "Command execution timeout"
        except Exception as e:
            result['error'] = f"Unexpected error: {str(e)}"
            logger.error(f"Command execution on {host}: {str(e)}")
        
        finally:
            if client:
                try:
                    client.close()
                except:
                    pass
        
        return result
    
    def concurrent_test_connections(self, hosts: List[str], port: int = 22, 
                                  username: str = None, password: str = None, 
                                  key_file: str = None, max_workers: int = 10) -> List[Dict[str, Any]]:
        """Test SSH connections to multiple hosts concurrently"""
        
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
            transient=True
        ) as progress:
            
            task = progress.add_task(f"Testing SSH connections to {len(hosts)} hosts", total=len(hosts))
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all tasks
                future_to_host = {
                    executor.submit(self.test_connection, host, port, username, password, key_file): host
                    for host in hosts
                }
                
                # Process completed tasks
                for future in as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        result = future.result()
                        results.append(result)
                        
                        # Update progress
                        progress.update(task, advance=1)
                        
                        # Show successful connections
                        if result['connected']:
                            auth_method = result.get('auth_method', 'unknown')
                            console.print(f"[green]✓ SSH connected: {result['host']}:{result['port']} ({auth_method})[/green]")
                        else:
                            console.print(f"[red]✗ SSH failed: {result['host']}:{result['port']} - {result['error']}[/red]")
                            
                    except Exception as e:
                        console.print(f"[red]Error testing {host}: {e}[/red]")
                        progress.update(task, advance=1)
        
        return results
    
    def find_ssh_keys(self, ssh_dir: str = None) -> List[str]:
        """Find SSH private keys in the system"""
        if not ssh_dir:
            ssh_dir = os.path.expanduser("~/.ssh")
        
        key_files = []
        ssh_path = Path(ssh_dir)
        
        if not ssh_path.exists():
            return key_files
        
        # Common SSH key filenames
        key_names = ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519']
        
        for key_name in key_names:
            key_path = ssh_path / key_name
            if key_path.exists() and key_path.is_file():
                try:
                    # Test if key is readable
                    with open(key_path, 'r') as f:
                        content = f.read()
                        if 'BEGIN' in content and 'PRIVATE KEY' in content:
                            key_files.append(str(key_path))
                except:
                    pass
        
        return key_files
    
    def try_multiple_auth_methods(self, host: str, port: int = 22, 
                                 username: str = None, password: str = None) -> Dict[str, Any]:
        """Try multiple authentication methods for SSH connection"""
        
        result = {
            'host': host,
            'port': port,
            'username': username,
            'connected': False,
            'auth_method': None,
            'error': None,
            'attempts': []
        }
        
        # Try password authentication first
        if password:
            console.print(f"[yellow]Trying password authentication for {host}...[/yellow]")
            auth_result = self.test_connection(host, port, username, password)
            result['attempts'].append({
                'method': 'password',
                'success': auth_result['connected'],
                'error': auth_result.get('error')
            })
            
            if auth_result['connected']:
                result['connected'] = True
                result['auth_method'] = 'password'
                result['server_info'] = auth_result.get('server_info')
                return result
        
        # Try SSH key authentication
        ssh_keys = self.find_ssh_keys()
        for key_file in ssh_keys:
            console.print(f"[yellow]Trying key authentication with {key_file} for {host}...[/yellow]")
            auth_result = self.test_connection(host, port, username, key_file=key_file)
            result['attempts'].append({
                'method': f'key:{key_file}',
                'success': auth_result['connected'],
                'error': auth_result.get('error')
            })
            
            if auth_result['connected']:
                result['connected'] = True
                result['auth_method'] = f'key:{key_file}'
                result['server_info'] = auth_result.get('server_info')
                return result
        
        # If no method worked, set error
        if result['attempts']:
            result['error'] = f"All authentication methods failed ({len(result['attempts'])} attempts)"
        else:
            result['error'] = "No authentication methods available"
        
        return result
    
    def try_multiple_credentials(self, host: str, port: int = 22, 
                                credentials: List[Dict[str, str]] = None) -> Dict[str, Any]:
        """Try multiple username/password combinations for SSH connection"""
        
        result = {
            'host': host,
            'port': port,
            'connected': False,
            'auth_method': None,
            'successful_credential': None,
            'error': None,
            'attempts': []
        }
        
        if not credentials:
            result['error'] = "No credentials provided"
            return result
        
        # Try each credential pair
        for i, cred in enumerate(credentials):
            username = cred.get('username')
            password = cred.get('password')
            key_file = cred.get('key_file')
            
            if not username:
                console.print(f"[yellow]Skipping credential {i+1} - no username[/yellow]")
                continue
            
            console.print(f"[yellow]Trying credential {i+1}: {username}@{host}...[/yellow]")
            
            # Try password authentication
            if password:
                auth_result = self.test_connection(host, port, username, password)
                result['attempts'].append({
                    'credential_index': i,
                    'username': username,
                    'method': 'password',
                    'success': auth_result['connected'],
                    'error': auth_result.get('error')
                })
                
                if auth_result['connected']:
                    result['connected'] = True
                    result['auth_method'] = 'password'
                    result['successful_credential'] = {'username': username, 'method': 'password'}
                    result['server_info'] = auth_result.get('server_info')
                    result['connection_time'] = auth_result.get('connection_time')
                    console.print(f"[green]✓ Authentication successful: {username}@{host} (password)[/green]")
                    return result
            
            # Try key authentication
            if key_file:
                auth_result = self.test_connection(host, port, username, key_file=key_file)
                result['attempts'].append({
                    'credential_index': i,
                    'username': username,
                    'method': f'key:{key_file}',
                    'success': auth_result['connected'],
                    'error': auth_result.get('error')
                })
                
                if auth_result['connected']:
                    result['connected'] = True
                    result['auth_method'] = f'key:{key_file}'
                    result['successful_credential'] = {'username': username, 'method': f'key:{key_file}'}
                    result['server_info'] = auth_result.get('server_info')
                    result['connection_time'] = auth_result.get('connection_time')
                    console.print(f"[green]✓ Authentication successful: {username}@{host} (key)[/green]")
                    return result
            
            # If neither password nor key_file provided, try SSH key discovery
            if not password and not key_file:
                ssh_keys = self.find_ssh_keys()
                for key_file_path in ssh_keys:
                    console.print(f"[yellow]Trying {username}@{host} with key {key_file_path}...[/yellow]")
                    auth_result = self.test_connection(host, port, username, key_file=key_file_path)
                    result['attempts'].append({
                        'credential_index': i,
                        'username': username,
                        'method': f'key:{key_file_path}',
                        'success': auth_result['connected'],
                        'error': auth_result.get('error')
                    })
                    
                    if auth_result['connected']:
                        result['connected'] = True
                        result['auth_method'] = f'key:{key_file_path}'
                        result['successful_credential'] = {'username': username, 'method': f'key:{key_file_path}'}
                        result['server_info'] = auth_result.get('server_info')
                        result['connection_time'] = auth_result.get('connection_time')
                        console.print(f"[green]✓ Authentication successful: {username}@{host} (key)[/green]")
                        return result
        
        # If no credential worked, set error
        if result['attempts']:
            result['error'] = f"All credentials failed ({len(result['attempts'])} attempts)"
        else:
            result['error'] = "No valid credentials provided"
        
        return result
    
    def concurrent_test_multiple_credentials(self, hosts: List[str], port: int = 22, 
                                           credentials: List[Dict[str, str]] = None, 
                                           max_workers: int = 10) -> List[Dict[str, Any]]:
        """Test multiple credentials on multiple hosts concurrently"""
        
        results = []
        
        if not credentials:
            # Return empty results if no credentials provided
            return [{'host': host, 'connected': False, 'error': 'No credentials provided'} for host in hosts]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
            transient=True
        ) as progress:
            
            task = progress.add_task(f"Testing credentials on {len(hosts)} hosts", total=len(hosts))
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all tasks
                future_to_host = {
                    executor.submit(self.try_multiple_credentials, host, port, credentials): host
                    for host in hosts
                }
                
                # Process completed tasks
                for future in as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        result = future.result()
                        results.append(result)
                        
                        # Update progress
                        progress.update(task, advance=1)
                        
                        # Show results
                        if result['connected']:
                            cred_info = result.get('successful_credential', {})
                            username = cred_info.get('username', 'unknown')
                            method = cred_info.get('method', 'unknown')
                            console.print(f"[green]✓ SSH connected: {username}@{result['host']}:{result['port']} ({method})[/green]")
                        else:
                            attempt_count = len(result.get('attempts', []))
                            console.print(f"[red]✗ SSH failed: {result['host']}:{result['port']} - {result['error']} ({attempt_count} attempts)[/red]")
                            
                    except Exception as e:
                        console.print(f"[red]Error testing {host}: {e}[/red]")
                        results.append({
                            'host': host,
                            'connected': False,
                            'error': f"Unexpected error: {str(e)}",
                            'attempts': []
                        })
                        progress.update(task, advance=1)
        
        return results
    
    def get_connection_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get summary statistics from SSH connection results"""
        total_hosts = len(results)
        successful_connections = len([r for r in results if r['connected']])
        failed_connections = total_hosts - successful_connections
        
        # Count authentication methods
        auth_methods = {}
        for result in results:
            if result['connected']:
                method = result.get('auth_method', 'unknown')
                auth_methods[method] = auth_methods.get(method, 0) + 1
        
        return {
            'total_hosts': total_hosts,
            'successful_connections': successful_connections,
            'failed_connections': failed_connections,
            'success_rate': (successful_connections / total_hosts * 100) if total_hosts > 0 else 0,
            'auth_methods': auth_methods
        } 