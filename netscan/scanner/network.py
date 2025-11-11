"""
Network discovery module for NetScan

This module handles network discovery and SSH port detection using python-nmap.
"""

import nmap
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
import ipaddress
import socket
import time

from ..utils.logging import get_logger, get_network_logger, LoggingContext
from ..utils.error_handling import (
    NetworkError, ConnectionTimeoutError, HostUnreachableError,
    GracefulErrorHandler, map_exception
)

logger = get_logger("scanner.network")
network_logger = get_network_logger()
console = Console()


class NetworkScanner:
    """Network scanner class for discovering SSH-enabled hosts"""
    
    def __init__(self, timeout: int = 5, threads: int = 10, max_retries: int = 0):
        self.timeout = timeout
        self.threads = threads
        self.max_retries = max(0, max_retries or 0)
        self.nm = nmap.PortScanner()
    
    def validate_ip_range(self, ip_range: str) -> bool:
        """Validate IP range format"""
        try:
            ipaddress.ip_network(ip_range, strict=False)
            return True
        except ValueError:
            return False
    
    def expand_ip_range(self, ip_range: str) -> List[str]:
        """Expand IP range to list of individual IPs"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            # Single IP
            try:
                ipaddress.ip_address(ip_range)
                return [ip_range]
            except ValueError:
                return []
    
    def check_ssh_port(self, ip: str, port: int = 22) -> Dict[str, Any]:
        """Check if SSH port is open on a specific host with configurable retries"""
        attempt = 0

        while True:
            try:
                return self._check_ssh_port_once(ip, port)
            except (ConnectionTimeoutError, HostUnreachableError, NetworkError) as exc:
                if attempt < self.max_retries:
                    attempt += 1
                    logger.debug(f"Retrying {ip}:{port} due to {exc.__class__.__name__} ({attempt}/{self.max_retries})")
                    continue
                raise
            except Exception as exc:
                if attempt < self.max_retries:
                    attempt += 1
                    logger.debug(f"Retrying {ip}:{port} due to unexpected error {exc} ({attempt}/{self.max_retries})")
                    continue
                raise

    def _check_ssh_port_once(self, ip: str, port: int = 22) -> Dict[str, Any]:
        """Single attempt to check if SSH port is open"""
        result = {
            'ip_address': ip,
            'ssh_port': port,
            'status': 'inactive',
            'hostname': None,
            'error': None,
            'response_time': None
        }
        
        start_time = time.time()
        network_logger.log_connection_attempt(ip, port)
        
        with GracefulErrorHandler(f"SSH port check for {ip}:{port}", logger, reraise=False):
            try:
                # Try to connect to SSH port
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                connection_result = sock.connect_ex((ip, port))
                duration = time.time() - start_time
                
                if connection_result == 0:
                    result['status'] = 'active'
                    network_logger.log_connection_success(ip, port, duration)
                    
                    # Try to get hostname
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                        result['hostname'] = hostname
                        logger.debug(f"Resolved hostname for {ip}: {hostname}")
                    except socket.herror as e:
                        result['hostname'] = None
                        logger.debug(f"Could not resolve hostname for {ip}: {e}")
                    
                    # Try to get SSH banner
                    try:
                        sock.settimeout(3)  # Shorter timeout for banner
                        banner = sock.recv(1024).decode().strip()
                        result['ssh_banner'] = banner
                        logger.debug(f"SSH banner for {ip}: {banner}")
                    except Exception as e:
                        result['ssh_banner'] = None
                        logger.debug(f"Could not get SSH banner for {ip}: {e}")
                else:
                    network_logger.log_connection_failure(ip, port, f"Connection refused (code: {connection_result})", duration)
                
                sock.close()
                
            except socket.timeout:
                duration = time.time() - start_time
                result['status'] = 'timeout'
                result['error'] = 'Connection timeout'
                network_logger.log_timeout(ip, port, self.timeout)
                raise ConnectionTimeoutError(f"Connection to {ip}:{port} timed out", host=ip, port=port, timeout=self.timeout)
                
            except socket.gaierror as e:
                duration = time.time() - start_time
                result['status'] = 'error'
                result['error'] = f"Name resolution failed: {e}"
                network_logger.log_connection_failure(ip, port, f"Name resolution failed: {e}", duration)
                raise HostUnreachableError(f"Could not resolve host {ip}", host=ip)
                
            except socket.error as e:
                duration = time.time() - start_time
                result['status'] = 'error'
                result['error'] = str(e)
                network_logger.log_connection_failure(ip, port, str(e), duration)
                raise NetworkError(f"Network error connecting to {ip}:{port}: {e}")
                
            except Exception as e:
                duration = time.time() - start_time
                result['status'] = 'error'
                result['error'] = f"Unexpected error: {str(e)}"
                network_logger.log_connection_failure(ip, port, f"Unexpected error: {e}", duration)
                mapped_error = map_exception(e)
                raise mapped_error
        
        result['response_time'] = time.time() - start_time
        return result
    
    def nmap_scan(self, ip_range: str, ports: str = "22") -> List[Dict[str, Any]]:
        """Perform nmap scan on IP range"""
        results = []
        
        try:
            console.print(f"[yellow]Running nmap scan on {ip_range}...[/yellow]")
            
            # Perform nmap scan
            scan_result = self.nm.scan(hosts=ip_range, ports=ports, arguments='-sS -T4')
            
            for host in scan_result['scan']:
                host_info = scan_result['scan'][host]
                
                result = {
                    'ip_address': host,
                    'hostname': host_info.get('hostname', None),
                    'status': 'inactive',
                    'ssh_port': 22,
                    'error': None
                }
                
                # Check if host is up
                if host_info['status']['state'] == 'up':
                    # Check SSH port
                    tcp_ports = host_info.get('tcp', {})
                    if 22 in tcp_ports:
                        port_info = tcp_ports[22]
                        if port_info['state'] == 'open':
                            result['status'] = 'active'
                            result['ssh_banner'] = port_info.get('name', 'ssh')
                
                results.append(result)
        
        except Exception as e:
            console.print(f"[red]Error during nmap scan: {e}[/red]")
            return []
        
        return results
    
    def concurrent_scan(self, ip_list: List[str], port: int = 22) -> List[Dict[str, Any]]:
        """Perform concurrent SSH port scanning"""
        results = []
        completed_count = 0
        error_count = 0
        active_count = 0
        
        with LoggingContext(logger, f"Concurrent scan of {len(ip_list)} hosts"):
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
                console=console,
                transient=True
            ) as progress:
                
                task = progress.add_task(f"Scanning {len(ip_list)} hosts", total=len(ip_list))
                
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    # Submit all tasks
                    future_to_ip = {
                        executor.submit(self.check_ssh_port, ip, port): ip 
                        for ip in ip_list
                    }
                    
                    # Process completed tasks
                    for future in as_completed(future_to_ip):
                        ip = future_to_ip[future]
                        completed_count += 1
                        
                        try:
                            result = future.result()
                            results.append(result)
                            
                            # Show active hosts
                            if result['status'] == 'active':
                                active_count += 1
                                console.print(f"[green]✓ Found SSH: {result['ip_address']}:{result['ssh_port']}[/green]")
                                logger.info(f"Active SSH host found: {result['ip_address']}:{result['ssh_port']}")
                            elif result['status'] == 'timeout':
                                logger.debug(f"Timeout scanning {ip}:{port}")
                            elif result['status'] == 'error':
                                error_count += 1
                                logger.debug(f"Error scanning {ip}:{port}: {result['error']}")
                            
                            # Log progress periodically
                            if completed_count % 50 == 0:
                                network_logger.log_scan_progress(completed_count, len(ip_list), ip)
                            
                        except Exception as e:
                            error_count += 1
                            logger.warning(f"Exception scanning {ip}: {e}")
                            console.print(f"[red]Error scanning {ip}: {e}[/red]")
                            
                            # Create error result
                            error_result = {
                                'ip_address': ip,
                                'ssh_port': port,
                                'status': 'error',
                                'hostname': None,
                                'error': str(e),
                                'response_time': None
                            }
                            results.append(error_result)
                        
                        finally:
                            progress.update(task, advance=1)
            
            # Log final scan statistics
            logger.info(f"Scan completed: {len(ip_list)} total, {active_count} active, {error_count} errors")
        
        return results
    
    def scan_range(self, ip_range: str, port: int = 22, use_nmap: bool = True) -> List[Dict[str, Any]]:
        """Scan IP range for SSH-enabled hosts"""
        
        # Validate IP range
        if not self.validate_ip_range(ip_range):
            console.print(f"[red]Invalid IP range: {ip_range}[/red]")
            return []
        
        console.print(f"[cyan]Scanning range: {ip_range}[/cyan]")
        console.print(f"[cyan]SSH port: {port}[/cyan]")
        console.print(f"[cyan]Timeout: {self.timeout}s[/cyan]")
        console.print(f"[cyan]Threads: {self.threads}[/cyan]")
        
        # Try nmap first (if available and requested)
        if use_nmap:
            try:
                results = self.nmap_scan(ip_range, str(port))
                if results:
                    console.print(f"[green]Found {len([r for r in results if r['status'] == 'active'])} active SSH hosts[/green]")
                    return results
            except Exception as e:
                console.print(f"[yellow]Nmap scan failed, falling back to socket scan: {e}[/yellow]")
        
        # Fallback to socket scanning
        ip_list = self.expand_ip_range(ip_range)
        if not ip_list:
            console.print(f"[red]Could not expand IP range: {ip_range}[/red]")
            return []
        
        console.print(f"[yellow]Performing socket scan on {len(ip_list)} hosts[/yellow]")
        results = self.concurrent_scan(ip_list, port)
        
        # Summary
        active_hosts = [r for r in results if r['status'] == 'active']
        console.print(f"[green]Scan complete: {len(active_hosts)} active SSH hosts found[/green]")
        
        return results
    
    def get_scan_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get summary statistics from scan results"""
        total_hosts = len(results)
        active_hosts = len([r for r in results if r['status'] == 'active'])
        inactive_hosts = len([r for r in results if r['status'] == 'inactive'])
        error_hosts = len([r for r in results if r['status'] == 'error'])
        timeout_hosts = len([r for r in results if r['status'] == 'timeout'])
        
        return {
            'total_hosts': total_hosts,
            'active_hosts': active_hosts,
            'inactive_hosts': inactive_hosts,
            'error_hosts': error_hosts,
            'timeout_hosts': timeout_hosts,
            'success_rate': (active_hosts / total_hosts * 100) if total_hosts > 0 else 0
        } 