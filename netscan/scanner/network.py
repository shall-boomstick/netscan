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
    
    def __init__(
        self,
        timeout: int = 3,
        threads: int = 10,
        max_retries: int = 0,
        additional_ports: Optional[List[int]] = None,
    ):
        self.timeout = timeout
        self.threads = threads
        self.max_retries = max(0, max_retries or 0)
        self.additional_ports = self._sanitize_ports(additional_ports or [])
        self.nm = nmap.PortScanner()
    
    def _sanitize_ports(self, ports: List[int]) -> List[int]:
        """Sanitize a collection of ports into a unique, sorted list"""
        normalized = []
        for candidate in ports:
            try:
                port = int(candidate)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535 and port not in normalized:
                normalized.append(port)
        return sorted(normalized)
    
    def _build_port_list(self, primary_port: int, extra_ports: Optional[List[int]] = None) -> List[int]:
        """Combine primary port with configured extra ports"""
        ports = []
        if primary_port and primary_port not in ports:
            ports.append(primary_port)
        for port in (extra_ports if extra_ports is not None else self.additional_ports):
            if port not in ports:
                ports.append(port)
        return sorted(ports)
    
    def _should_capture_banner(self, port: int) -> bool:
        """Determine whether we should attempt to capture a service banner"""
        return port == 22
    
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
            'port': port,
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
                    if self._should_capture_banner(port):
                        try:
                            sock.settimeout(3)  # Shorter timeout for banner
                            banner = sock.recv(1024).decode(errors="ignore").strip()
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
    
    def nmap_scan(
        self,
        ip_range: str,
        primary_port: int = 22,
        extra_ports: Optional[List[int]] = None,
    ) -> List[Dict[str, Any]]:
        """Perform nmap scan on IP range"""
        port_list = self._build_port_list(primary_port, extra_ports)
        if not port_list:
            port_list = [primary_port]
        ports_arg = ",".join(str(p) for p in port_list)
        
        def process_scan(scan_output) -> List[Dict[str, Any]]:
            processed_results: List[Dict[str, Any]] = []
            for host in scan_output.get('scan', {}):
                host_info = scan_output['scan'][host]
                entry = {
                    'ip_address': host,
                    'hostname': host_info.get('hostname', None),
                    'status': 'inactive',
                    'ssh_port': primary_port,
                    'port': primary_port,
                    'error': None,
                    'open_ports': [],
                    'ports_scanned': list(port_list),
                }
                
                if host_info['status']['state'] == 'up':
                    tcp_ports = host_info.get('tcp', {})
                    for port in port_list:
                        port_info = tcp_ports.get(port)
                        if port_info and port_info.get('state') == 'open':
                            service = port_info.get('name')
                            entry['open_ports'].append({'port': port, 'service': service})
                            if port == primary_port:
                                entry['status'] = 'active'
                                entry['ssh_banner'] = service
                processed_results.append(entry)
            return processed_results
        
        results: List[Dict[str, Any]] = []
        
        try:
            console.print(f"[yellow]Running nmap scan on {ip_range} (ports: {ports_arg})...[/yellow]")
            
            # Try TCP connect scan first (doesn't require root)
            # -sT = TCP connect scan (safe for non-root users)
            # -T4 = Aggressive timing template (faster)
            scan_result = self.nm.scan(hosts=ip_range, ports=ports_arg, arguments='-sT -T4')
            results = process_scan(scan_result)
        
        except Exception as e:
            error_msg = str(e)
            if 'root privileges' in error_msg.lower() or 'requires root' in error_msg.lower():
                console.print(f"[yellow]Nmap requires root privileges for advanced scans. Using TCP connect scan...[/yellow]")
                try:
                    # Fallback to basic TCP connect scan without timing
                    scan_result = self.nm.scan(hosts=ip_range, ports=ports_arg, arguments='-sT')
                    results = process_scan(scan_result)
                except Exception as fallback_error:
                    console.print(f"[red]Nmap fallback scan also failed: {fallback_error}[/red]")
                    logger.warning(f"Nmap scan failed completely: {fallback_error}")
                    return []
            else:
                console.print(f"[red]Error during nmap scan: {e}[/red]")
                logger.warning(f"Nmap scan failed: {e}")
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
                                console.print(f"[green]✓ Open port {result['port']} detected on {result['ip_address']}[/green]")
                                logger.info(f"Active port found: {result['ip_address']}:{result['port']}")
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
                                'port': port,
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
        
        port_list = self._build_port_list(port)
        additional_only = [p for p in port_list if p != port]
        if additional_only:
            console.print(f"[cyan]Additional ports: {', '.join(str(p) for p in additional_only)}[/cyan]")
        
        # Try nmap first (if available and requested)
        if use_nmap:
            try:
                results = self.nmap_scan(ip_range, primary_port=port, extra_ports=self.additional_ports)
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
        host_results: Dict[str, Dict[str, Any]] = {}
        
        for scan_port in port_list:
            port_results = self.concurrent_scan(ip_list, scan_port)
            for result in port_results:
                ip_addr = result['ip_address']
                entry = host_results.setdefault(ip_addr, {
                    'ip_address': ip_addr,
                    'hostname': result.get('hostname'),
                    'status': 'inactive',
                    'ssh_port': port,
                    'port': port,
                    'error': None,
                    'open_ports': [],
                    'ports_scanned': [],
                    'timeouts': [],
                    'errors': [],
                    'response_times': {}
                })
                
                if result.get('hostname') and not entry.get('hostname'):
                    entry['hostname'] = result.get('hostname')
                
                if scan_port not in entry['ports_scanned']:
                    entry['ports_scanned'].append(scan_port)
                
                if result['status'] == 'active':
                    service = result.get('ssh_banner') if scan_port == port else None
                    entry['open_ports'].append({'port': scan_port, 'service': service})
                    if scan_port == port:
                        entry['status'] = 'active'
                        if service:
                            entry['ssh_banner'] = service
                elif result['status'] == 'timeout':
                    entry['timeouts'].append(scan_port)
                elif result['status'] == 'error':
                    entry['errors'].append({'port': scan_port, 'error': result.get('error')})
                
                if result.get('response_time') is not None:
                    entry['response_times'][scan_port] = result['response_time']
        
        results = list(host_results.values())
        
        # Summary
        active_hosts = [r for r in results if r['status'] == 'active']
        console.print(f"[green]Scan complete: {len(active_hosts)} active SSH hosts found[/green]")
        
        return results
    
    def scan_range_with_nmap(self, ip_range: str, port: int = 22) -> List[Dict[str, Any]]:
        """Scan IP range using nmap and return only active SSH hosts"""
        
        port_list = self._build_port_list(port)
        ports_display = ", ".join(str(p) for p in port_list)
        console.print(f"[cyan]Nmap scanning range: {ip_range} (ports: {ports_display})[/cyan]")
        
        try:
            # Use nmap to scan for active SSH hosts
            results = self.nmap_scan(ip_range, primary_port=port, extra_ports=self.additional_ports)
            
            # Filter to only return active hosts
            active_hosts = [r for r in results if r['status'] == 'active']
            
            console.print(f"[green]Nmap scan complete: {len(active_hosts)} active SSH hosts found[/green]")
            
            return active_hosts
            
        except Exception as e:
            console.print(f"[red]Nmap scan failed: {e}[/red]")
            logger.error(f"Nmap scan error for {ip_range}: {e}")
            return []
    
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