"""
Comprehensive scanner for NetScan

This module provides a complete scanning workflow that combines network discovery,
SSH authentication testing, and system information collection in a single operation.
"""

import json
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.panel import Panel
from rich.table import Table
import time

from .network import NetworkScanner
from .ssh import SSHConnector
from .collector import SystemInfoCollector
from ..utils.logging import get_logger
from ..config import config_manager

console = Console()
logger = get_logger("scanner.comprehensive")


class ComprehensiveScanner:
    """Comprehensive scanner that performs network discovery, authentication, and info collection"""
    
    def __init__(self, timeout: int = 5, threads: int = 10):
        self.timeout = timeout
        self.threads = threads
        
        # Initialize component scanners
        additional_ports = config_manager.get_additional_ports()
        self.network_scanner = NetworkScanner(
            timeout=timeout,
            threads=threads,
            additional_ports=additional_ports
        )
        self.ssh_connector = SSHConnector(timeout=timeout)
        self.info_collector = SystemInfoCollector(self.ssh_connector)
    
    def comprehensive_scan(self, 
                          ip_range: str,
                          port: int = 22,
                          credentials: List[Dict[str, str]] = None,
                          store_db: bool = True,
                          use_nmap: bool = True,
                          progress_callback=None) -> Dict[str, Any]:
        """
        Perform comprehensive scan: network discovery -> auth testing -> info collection
        
        Args:
            ip_range: IP range to scan (CIDR notation or comma-separated IPs)
            port: SSH port to scan (default: 22)
            credentials: List of credential dictionaries with 'username' and 'password'/'key_file'
            store_db: Whether to store results in database
            use_nmap: Whether to use nmap for network discovery
            
        Returns:
            Dictionary with comprehensive scan results
        """
        
        results = {
            'scan_start_time': time.time(),
            'ip_range': ip_range,
            'port': port,
            'network_discovery': {
                'total_hosts_scanned': 0,
                'ssh_hosts_found': 0,
                'discovered_hosts': []
            },
            'authentication': {
                'hosts_tested': 0,
                'successful_auths': 0,
                'failed_auths': 0,
                'auth_results': []
            },
            'system_info': {
                'hosts_collected': 0,
                'successful_collections': 0,
                'failed_collections': 0,
                'collection_results': []
            },
            'database_storage': {
                'hosts_stored': 0,
                'storage_errors': []
            }
        }
        
        console.print(Panel.fit(
            "[bold cyan]NetScan - Comprehensive Network Analysis[/bold cyan]\n"
            "Complete workflow: Discovery → Authentication → Information Collection",
            border_style="cyan"
        ))
        
        if progress_callback:
            progress_callback(0.0, "Starting scan...")
        
        # Phase 1: Network Discovery
        console.print(f"\n[bold blue]Phase 1: Network Discovery[/bold blue]")
        console.print(f"Scanning range: {ip_range}")
        console.print(f"Target port: {port}")
        extra_ports = [p for p in self.network_scanner.additional_ports if p != port]
        if extra_ports:
            console.print(f"Additional ports: {', '.join(str(p) for p in extra_ports)}")
        
        discovered_hosts = []
        discovered_lookup = {}
        try:
            if use_nmap:
                # Use nmap for faster discovery
                discovered_hosts = self.network_scanner.scan_range_with_nmap(ip_range, port)
                if progress_callback:
                    progress_callback(0.25, f"Discovery complete: {len(discovered_hosts)} SSH hosts found")
            else:
                # Use socket-based scanning
                if ',' in ip_range:
                    # Multiple specific IPs
                    host_list = [ip.strip() for ip in ip_range.split(',')]
                else:
                    # IP range
                    host_list = self.network_scanner.expand_ip_range(ip_range)
                
                discovered_hosts = []
                total_hosts = len(host_list)
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    console=console,
                    transient=True
                ) as progress:
                    task = progress.add_task(f"Scanning {len(host_list)} hosts", total=len(host_list))
                    for idx, host in enumerate(host_list):
                        try:
                            result = self.network_scanner.check_ssh_port(host, port)
                            if result['status'] == 'active':
                                discovered_hosts.append(result)
                                console.print(f"[green]✓ Found SSH host: {host}:{port}[/green]")
                            progress.update(task, advance=1)
                        except Exception as e:
                            logger.error(f"Error scanning {host}: {e}")
                            progress.update(task, advance=1)
                        # Progress update for discovery phase
                        if progress_callback:
                            percent = 0.25 * ((idx + 1) / total_hosts)
                            progress_callback(percent, f"Discovery: {idx+1}/{total_hosts} hosts scanned")
                if progress_callback:
                    progress_callback(0.25, f"Discovery complete: {len(discovered_hosts)} SSH hosts found")
            
            # Update results
            results['network_discovery']['total_hosts_scanned'] = len(host_list) if not use_nmap else 0
            results['network_discovery']['ssh_hosts_found'] = len(discovered_hosts)
            results['network_discovery']['discovered_hosts'] = discovered_hosts
            discovered_lookup = {host['ip_address']: host for host in discovered_hosts}
            
            console.print(f"\n[green]Discovery complete: {len(discovered_hosts)} SSH hosts found[/green]")
            
            if not discovered_hosts:
                console.print("[yellow]No SSH-accessible hosts found. Scan complete.[/yellow]")
                results['scan_end_time'] = time.time()
                return results
            
        except Exception as e:
            console.print(f"[red]Network discovery failed: {e}[/red]")
            logger.error(f"Network discovery error: {e}")
            results['scan_end_time'] = time.time()
            return results
        
        # Phase 2: Authentication Testing
        console.print(f"\n[bold blue]Phase 2: Authentication Testing[/bold blue]")
        console.print(f"Testing credentials on {len(discovered_hosts)} hosts")
        
        if not credentials:
            console.print("[red]No credentials provided. Skipping authentication phase.[/red]")
            results['scan_end_time'] = time.time()
            return results
        
        auth_results = []
        successful_hosts = []
        
        try:
            host_ips = [host['ip_address'] for host in discovered_hosts]
            total_auth = len(host_ips)
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task(f"Testing credentials on {len(host_ips)} hosts", total=len(host_ips))
                for idx, host_ip in enumerate(host_ips):
                    try:
                        # Try multiple credentials on this host
                        auth_result = self.ssh_connector.try_multiple_credentials(host_ip, port, credentials)
                        auth_results.append(auth_result)
                        
                        if auth_result['connected']:
                            successful_hosts.append(auth_result)
                            cred_info = auth_result.get('successful_credential', {})
                            username = cred_info.get('username', 'unknown')
                            method = cred_info.get('method', 'unknown')
                            console.print(f"[green]✓ Authenticated: {username}@{host_ip} ({method})[/green]")
                        else:
                            attempt_count = len(auth_result.get('attempts', []))
                            console.print(f"[red]✗ Auth failed: {host_ip} ({attempt_count} attempts)[/red]")
                        
                        progress.update(task, advance=1)
                        # Progress update for auth phase
                        if progress_callback:
                            percent = 0.25 + 0.25 * ((idx + 1) / total_auth)
                            progress_callback(percent, f"Authentication: {idx+1}/{total_auth} hosts tested")
                    except Exception as e:
                        logger.error(f"Authentication error for {host_ip}: {e}")
                        auth_results.append({
                            'host': host_ip,
                            'connected': False,
                            'error': f"Authentication test failed: {str(e)}",
                            'attempts': []
                        })
                        progress.update(task, advance=1)
                        if progress_callback:
                            percent = 0.25 + 0.25 * ((idx + 1) / total_auth)
                            progress_callback(percent, f"Authentication: {idx+1}/{total_auth} hosts tested")
            # Update results
            results['authentication']['hosts_tested'] = len(auth_results)
            results['authentication']['successful_auths'] = len(successful_hosts)
            results['authentication']['failed_auths'] = len(auth_results) - len(successful_hosts)
            results['authentication']['auth_results'] = auth_results
            
            console.print(f"\n[green]Authentication complete: {len(successful_hosts)}/{len(auth_results)} hosts authenticated[/green]")
            
            if not successful_hosts:
                console.print("[yellow]No hosts authenticated. Skipping info collection.[/yellow]")
                results['scan_end_time'] = time.time()
                return results
                
        except Exception as e:
            console.print(f"[red]Authentication testing failed: {e}[/red]")
            logger.error(f"Authentication error: {e}")
            results['scan_end_time'] = time.time()
            return results
        
        # Phase 3: System Information Collection
        console.print(f"\n[bold blue]Phase 3: System Information Collection[/bold blue]")
        console.print(f"Collecting system info from {len(successful_hosts)} authenticated hosts")
        
        info_results = []
        successful_collections = []
        
        try:
            total_info = len(successful_hosts)
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task(f"Collecting info from {len(successful_hosts)} hosts", total=len(successful_hosts))
                for idx, auth_result in enumerate(successful_hosts):
                    try:
                        host_ip = auth_result['host']
                        cred_info = auth_result.get('successful_credential', {})
                        username = cred_info.get('username')
                        method = cred_info.get('method', '')
                        
                        # Determine authentication details
                        password = None
                        key_file = None
                        
                        if method == 'password':
                            # Find the password from credentials list
                            for cred in credentials:
                                if cred.get('username') == username and cred.get('password'):
                                    password = cred['password']
                                    break
                        elif method.startswith('key:'):
                            key_file = method.split(':', 1)[1]
                        
                        # Collect system information
                        info_result = self.info_collector.collect_system_info(
                            host_ip, port, username, password, key_file
                        )
                        
                        # Add authentication info to the result
                        info_result['successful_credential'] = cred_info
                        info_result['auth_attempts'] = len(auth_result.get('attempts', []))
                        
                        info_results.append(info_result)
                        
                        if info_result['collection_success']:
                            successful_collections.append(info_result)
                            console.print(f"[green]✓ Info collected: {host_ip} ({username})[/green]")
                        else:
                            error_count = len(info_result['collection_errors'])
                            console.print(f"[yellow]⚠ Partial info: {host_ip} ({error_count} errors)[/yellow]")
                        
                        progress.update(task, advance=1)
                        # Progress update for info phase
                        if progress_callback:
                            percent = 0.5 + 0.25 * ((idx + 1) / total_info)
                            progress_callback(percent, f"Info Collection: {idx+1}/{total_info} hosts processed")
                    except Exception as e:
                        logger.error(f"Info collection error for {host_ip}: {e}")
                        info_results.append({
                            'host': host_ip,
                            'collection_success': False,
                            'collection_errors': [f"Collection failed: {str(e)}"],
                            'raw_outputs': {},
                            'parsed_info': {}
                        })
                        progress.update(task, advance=1)
                        if progress_callback:
                            percent = 0.5 + 0.25 * ((idx + 1) / total_info)
                            progress_callback(percent, f"Info Collection: {idx+1}/{total_info} hosts processed")
            # Update results
            results['system_info']['hosts_collected'] = len(info_results)
            results['system_info']['successful_collections'] = len(successful_collections)
            results['system_info']['failed_collections'] = len(info_results) - len(successful_collections)
            results['system_info']['collection_results'] = info_results
            
            console.print(f"\n[green]Info collection complete: {len(successful_collections)}/{len(info_results)} hosts processed[/green]")
            
        except Exception as e:
            console.print(f"[red]System info collection failed: {e}[/red]")
            logger.error(f"Info collection error: {e}")
        
        # Phase 4: Database Storage
        if store_db and successful_collections:
            console.print(f"\n[bold blue]Phase 4: Database Storage[/bold blue]")
            console.print(f"Storing results for {len(successful_collections)} hosts")
            
            stored_count = 0
            storage_errors = []
            
            try:
                from ..database.operations import db_manager
                
                total_db = len(successful_collections)
                for idx, result in enumerate(successful_collections):
                    try:
                        # Prepare host data for database
                        parsed = result['parsed_info']
                        cred_info = result.get('successful_credential', {})
                        
                        host_data = {
                            'ip_address': result['host'],
                            'hostname': parsed.get('hostname', result['host']),
                            'ssh_port': result.get('port', port),
                            'os_info': parsed.get('os_info', 'Unknown'),
                            'kernel_version': parsed.get('kernel_version', 'Unknown'),
                            'status': 'active',
                            'working_username': cred_info.get('username'),
                            'auth_method': cred_info.get('method'),
                            'auth_attempts': result.get('auth_attempts', 0)
                        }
                        discovered_entry = discovered_lookup.get(result['host'], {})
                        host_data['open_ports'] = json.dumps(discovered_entry.get('open_ports', []))
                        
                        # Add system info if available
                        if 'memory' in parsed:
                            mem = parsed['memory']
                            host_data['memory_total'] = mem.get('total_mb')
                            host_data['memory_used'] = mem.get('used_mb')
                        
                        if 'cpu' in parsed:
                            cpu = parsed['cpu']
                            host_data['cpu_info'] = cpu.get('model')
                        
                        if 'uptime' in parsed:
                            uptime = parsed['uptime']
                            host_data['uptime'] = uptime.get('raw')
                        
                        if 'disk' in parsed:
                            import json
                            host_data['disk_usage'] = json.dumps(parsed['disk'])
                        
                        # Store in database
                        db_manager.create_host(host_data)
                        stored_count += 1
                        
                        console.print(f"[green]✓ Stored: {result['host']} ({cred_info.get('username')})[/green]")
                        # Progress update for db phase
                        if progress_callback:
                            percent = 0.75 + 0.25 * ((idx + 1) / total_db)
                            progress_callback(percent, f"Database: {idx+1}/{total_db} hosts stored")
                    except Exception as e:
                        error_msg = f"Storage error for {result['host']}: {str(e)}"
                        storage_errors.append(error_msg)
                        logger.error(error_msg)
                        console.print(f"[red]✗ Storage failed: {result['host']} - {str(e)}[/red]")
                        if progress_callback:
                            percent = 0.75 + 0.25 * ((idx + 1) / total_db)
                            progress_callback(percent, f"Database: {idx+1}/{total_db} hosts stored (with errors)")
                # Update results
                results['database_storage']['hosts_stored'] = stored_count
                results['database_storage']['storage_errors'] = storage_errors
                
                console.print(f"\n[green]Database storage complete: {stored_count} hosts stored[/green]")
                if progress_callback:
                    progress_callback(1.0, "Scan complete!")
            
            except Exception as e:
                console.print(f"[red]Database storage failed: {e}[/red]")
                logger.error(f"Database storage error: {e}")
                if progress_callback:
                    progress_callback(1.0, f"Scan complete with DB error: {e}")
        else:
            if progress_callback:
                progress_callback(1.0, "Scan complete!")
        
        # Final summary
        results['scan_end_time'] = time.time()
        scan_duration = results['scan_end_time'] - results['scan_start_time']
        
        self._display_comprehensive_summary(results, scan_duration)
        
        return results
    
    def _display_comprehensive_summary(self, results: Dict[str, Any], duration: float):
        """Display comprehensive scan summary"""
        
        console.print(f"\n{Panel.fit('[bold green]Comprehensive Scan Complete[/bold green]', border_style='green')}")
        
        # Create summary table
        table = Table(title="Scan Summary", show_header=True, header_style="bold blue")
        table.add_column("Phase", style="cyan", no_wrap=True)
        table.add_column("Metric", style="white")
        table.add_column("Count", style="green", justify="right")
        
        # Network Discovery
        net = results['network_discovery']
        table.add_row("Discovery", "SSH hosts found", str(net['ssh_hosts_found']))
        
        # Authentication
        auth = results['authentication']
        table.add_row("Authentication", "Hosts tested", str(auth['hosts_tested']))
        table.add_row("", "Successful auths", str(auth['successful_auths']))
        table.add_row("", "Failed auths", str(auth['failed_auths']))
        
        # System Info
        info = results['system_info']
        table.add_row("Info Collection", "Hosts processed", str(info['hosts_collected']))
        table.add_row("", "Successful collections", str(info['successful_collections']))
        table.add_row("", "Failed collections", str(info['failed_collections']))
        
        # Database
        db = results['database_storage']
        table.add_row("Database", "Hosts stored", str(db['hosts_stored']))
        table.add_row("", "Storage errors", str(len(db['storage_errors'])))
        
        # Timing
        table.add_row("Timing", "Total duration", f"{duration:.1f}s")
        
        console.print(table)
        
        # Success rate
        if auth['hosts_tested'] > 0:
            auth_success_rate = (auth['successful_auths'] / auth['hosts_tested']) * 100
            console.print(f"\n[cyan]Authentication Success Rate:[/cyan] {auth_success_rate:.1f}%")
        
        if info['hosts_collected'] > 0:
            info_success_rate = (info['successful_collections'] / info['hosts_collected']) * 100
            console.print(f"[cyan]Info Collection Success Rate:[/cyan] {info_success_rate:.1f}%") 