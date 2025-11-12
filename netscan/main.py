#!/usr/bin/env python3
"""
NetScan - SSH Network Scanner
Main CLI entry point using Click
"""

import click
import json
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
import os
import sys
from datetime import datetime

from .scanner.network import NetworkScanner
from .scanner.ssh import SSHConnector
from .scanner.collector import SystemInfoCollector
from .scanner.comprehensive import ComprehensiveScanner
from .utils.validators import validate_ip_range, validate_port, validate_username, validate_timeout, validate_threads

# Initialize Rich console
console = Console()

@click.group()
@click.version_option(version="0.1.0", prog_name="NetScan")
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.pass_context
def cli(ctx, debug):
    """
    NetScan - SSH Network Scanner
    
    A powerful CLI tool for discovering and analyzing Linux servers with SSH capability.
    """
    # Ensure that ctx.obj exists and is a dict
    ctx.ensure_object(dict)
    ctx.obj['debug'] = debug
    
    if debug:
        console.print("[yellow]Debug mode enabled[/yellow]")

@cli.group()
@click.pass_context
def scan(ctx):
    """Network scanning operations"""
    pass

@scan.command()
@click.option('--range', '-r', required=True, 
              help='IP range to scan (e.g., 192.168.1.0/24)')
@click.option('--username', '-u', 
              help='SSH username (can be set in config)')
@click.option('--password', '-p', 
              help='SSH password (can be set in config)',
              prompt=True, hide_input=True, prompt_required=False)
@click.option('--port', '-P', default=22, 
              help='SSH port (default: 22)')
@click.option('--threads', '-t', default=10, 
              help='Number of concurrent threads (default: 10)')
@click.option('--timeout', '-T', default=5, 
              help='Connection timeout in seconds (default: 5)')
@click.option('--retries', '-R', type=int, 
              help='Number of retry attempts for unreachable hosts (default from config)')
@click.option('--no-nmap', is_flag=True, 
              help='Skip nmap scan and use socket scan only')
@click.pass_context
def network(ctx, range, username, password, port, threads, timeout, retries, no_nmap):
    """Scan network range for SSH-enabled hosts"""
    
    # Welcome message
    console.print(Panel.fit(
        Text("NetScan - Network Scanner", style="bold cyan"),
        border_style="cyan"
    ))
    
    # Load stored defaults if explicit values not provided
    from .config import config_manager
    used_stored_username = False
    used_stored_password = False

    if not username:
        stored_username = config_manager.get_credential_value('username')
        if stored_username:
            username = stored_username
            used_stored_username = True

    if not password:
        stored_password = config_manager.get_credential_value('password')
        if stored_password:
            password = stored_password
            used_stored_password = True
    
    additional_ports = config_manager.get_additional_ports()
    
    # Validate inputs
    if not validate_ip_range(range):
        console.print(f"[red]Error: Invalid IP range: {range}[/red]")
        sys.exit(1)
    
    if not validate_port(port):
        console.print(f"[red]Error: Invalid port number: {port}[/red]")
        sys.exit(1)
    
    if not validate_threads(threads):
        console.print(f"[red]Error: Invalid thread count: {threads} (must be 1-100)[/red]")
        sys.exit(1)
    
    if not validate_timeout(timeout):
        console.print(f"[red]Error: Invalid timeout: {timeout} (must be 1-300 seconds)[/red]")
        sys.exit(1)

    # Determine retries
    if retries is None:
        retries = config_manager.get('scanning', 'max_retries', 0)
    try:
        retries = int(retries)
        if retries < 0 or retries > 10:
            raise ValueError
    except (TypeError, ValueError):
        console.print(f"[red]Error: Invalid retry count: {retries} (must be 0-10)[/red]")
        sys.exit(1)
    
    # Check for username/password (optional for network scan)
    if username and not validate_username(username):
        console.print(f"[red]Error: Invalid username format: {username}[/red]")
        sys.exit(1)
    
    console.print(f"[green]Scanning range:[/green] {range}")
    console.print(f"[green]SSH port:[/green] {port}")
    console.print(f"[green]Threads:[/green] {threads}")
    console.print(f"[green]Timeout:[/green] {timeout}s")
    console.print(f"[green]Retries:[/green] {retries}")
    
    if username:
        suffix = " [dim](stored)[/dim]" if used_stored_username else ""
        console.print(f"[green]Username:[/green] {username}{suffix}")
    if password:
        suffix = " [dim](stored)[/dim]" if used_stored_password else ""
        console.print(f"[yellow]Password:[/yellow] [redacted]{suffix}")
    
    try:
        # Initialize scanner
        scanner = NetworkScanner(
            timeout=timeout,
            threads=threads,
            max_retries=retries,
            additional_ports=additional_ports,
        )
        
        # Perform network scan
        results = scanner.scan_range(range, port=port, use_nmap=not no_nmap)
        
        if not results:
            console.print("[yellow]No hosts found or scan failed[/yellow]")
            return
        
        # Get scan summary
        summary = scanner.get_scan_summary(results)
        
        # Display results
        console.print("\n[bold blue]Scan Summary:[/bold blue]")
        console.print(f"[green]Total hosts scanned:[/green] {summary['total_hosts']}")
        console.print(f"[green]Active SSH hosts:[/green] {summary['active_hosts']}")
        console.print(f"[yellow]Inactive hosts:[/yellow] {summary['inactive_hosts']}")
        console.print(f"[red]Error hosts:[/red] {summary['error_hosts']}")
        console.print(f"[red]Timeout hosts:[/red] {summary['timeout_hosts']}")
        console.print(f"[cyan]Success rate:[/cyan] {summary['success_rate']:.1f}%")
        
        if additional_ports:
            from rich.table import Table
            
            extra_port_counts = {}
            host_port_rows = []
            for host_result in results:
                extra_open = [
                    str(port_info['port'])
                    for port_info in host_result.get('open_ports', [])
                    if port_info['port'] != port
                ]
                for port_num in extra_open:
                    extra_port_counts[port_num] = extra_port_counts.get(port_num, 0) + 1
                if extra_open:
                    host_port_rows.append((host_result['ip_address'], ", ".join(sorted(extra_open))))
            
            console.print("\n[bold blue]Additional Port Findings[/bold blue]")
            if extra_port_counts:
                summary_table = Table(show_header=True, header_style="bold magenta")
                summary_table.add_column("Port", justify="right")
                summary_table.add_column("Open Hosts", justify="right")
                for port_num, count in sorted(extra_port_counts.items(), key=lambda item: int(item[0])):
                    summary_table.add_row(str(port_num), str(count))
                console.print(summary_table)
                
                host_table = Table(show_header=True, header_style="bold cyan")
                host_table.add_column("Host")
                host_table.add_column("Open Additional Ports")
                for ip_address, ports_str in sorted(host_port_rows):
                    host_table.add_row(ip_address, ports_str)
                console.print(host_table)
            else:
                console.print("[cyan]No additional ports were detected as open.[/cyan]")
        
        # Store results in database
        active_hosts = [r for r in results if r['status'] == 'active']
        if active_hosts:
            console.print(f"\n[blue]Storing {len(active_hosts)} active hosts in database...[/blue]")
            
            from .database.operations import db_manager
            
            for host_result in active_hosts:
                # Prepare host data for database
                open_ports_payload = host_result.get('open_ports', [])
                host_data = {
                    'ip_address': host_result['ip_address'],
                    'hostname': host_result.get('hostname'),
                    'ssh_port': host_result['ssh_port'],
                    'status': 'active',
                    'open_ports': json.dumps(open_ports_payload)
                }
                
                # Create or update host in database
                try:
                    db_manager.create_host(host_data)
                except Exception as e:
                    console.print(f"[red]Error storing host {host_result['ip_address']}: {e}[/red]")
            
            console.print("[green]✓ Results stored in database[/green]")
        
        console.print(f"\n[bold green]Network scan completed successfully![/bold green]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error during scan: {e}[/red]")
        if ctx.obj.get('debug'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

@scan.command()
@click.option('--hosts', '-h', help='Comma-separated list of IP addresses/hostnames')
@click.option('--from-db', is_flag=True, help='Use hosts from database')
@click.option('--username', '-u', help='SSH username (falls back to stored credential)')
@click.option('--password', '-p', help='SSH password (falls back to stored credential)')
@click.option('--key-file', '-k', help='SSH private key file path')
@click.option('--multiple-usernames', help='Comma-separated list of usernames to try')
@click.option('--multiple-passwords', help='Comma-separated list of passwords to try')
@click.option('--credentials-file', help='File containing username:password pairs (one per line)')
@click.option('--try-multiple-credentials', is_flag=True, help='Try multiple username/password combinations')
@click.option('--port', '-P', default=22, help='SSH port (default: 22)')
@click.option('--timeout', '-T', default=5, help='Connection timeout in seconds (default: 5)')
@click.option('--threads', '-t', default=5, help='Number of concurrent threads (default: 5)')
@click.option('--try-all-methods', is_flag=True, help='Try all available authentication methods')
@click.pass_context
def auth(ctx, hosts, from_db, username, password, key_file, multiple_usernames, multiple_passwords, credentials_file, try_multiple_credentials, port, timeout, threads, try_all_methods):
    """Test SSH authentication to discovered hosts"""
    
    console.print(Panel.fit(
        Text("NetScan - SSH Authentication Test", style="bold green"),
        border_style="green"
    ))
    
    # Validate inputs
    if not validate_port(port):
        console.print(f"[red]Error: Invalid port number: {port}[/red]")
        sys.exit(1)
    
    if not validate_timeout(timeout):
        console.print(f"[red]Error: Invalid timeout: {timeout}[/red]")
        sys.exit(1)
    
    if not validate_threads(threads):
        console.print(f"[red]Error: Invalid thread count: {threads}[/red]")
        sys.exit(1)
    
    # Validate username for single credential mode
    if username and not validate_username(username):
        console.print(f"[red]Error: Invalid username format: {username}[/red]")
        sys.exit(1)
    
    # Get host list
    host_list = []
    
    if from_db:
        console.print("[blue]Loading hosts from database...[/blue]")
        try:
            from .database.operations import db_manager
            hosts_from_db = db_manager.get_all_hosts(status='active')
            host_list = [host.ip_address for host in hosts_from_db]
            console.print(f"[green]Found {len(host_list)} active hosts in database[/green]")
        except Exception as e:
            console.print(f"[red]Error loading hosts from database: {e}[/red]")
            sys.exit(1)
    
    elif hosts:
        host_list = [host.strip() for host in hosts.split(',')]
        console.print(f"[green]Testing {len(host_list)} specified hosts[/green]")
    
    else:
        console.print("[red]Error: Must specify either --hosts or --from-db[/red]")
        sys.exit(1)
    
    if not host_list:
        console.print("[yellow]No hosts to test[/yellow]")
        return
    
    from .config import config_manager
    used_stored_username = False
    used_stored_password = False
    used_stored_key = False
    
    if not username:
        stored_username = config_manager.get_credential_value('username')
        if stored_username:
            username = stored_username
            used_stored_username = True
    
    if not password:
        stored_password = config_manager.get_credential_value('password')
        if stored_password:
            password = stored_password
            used_stored_password = True
    
    if not key_file:
        stored_key = config_manager.get_credential_value('ssh_key_path')
        if stored_key:
            key_file = stored_key
            used_stored_key = True
    
    # Prepare credential list holder for multi-credential mode
    credentials_list = []
    
    if try_multiple_credentials:
        # Parse multiple credentials
        if credentials_file:
            console.print(f"[blue]Loading credentials from file: {credentials_file}[/blue]")
            try:
                with open(credentials_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if ':' in line:
                                cred_username, cred_password = line.split(':', 1)
                                credentials_list.append({
                                    'username': cred_username.strip(),
                                    'password': cred_password.strip()
                                })
                            else:
                                console.print(f"[yellow]Warning: Invalid credential format on line {line_num}: {line}[/yellow]")
                console.print(f"[green]Loaded {len(credentials_list)} credentials from file[/green]")
            except FileNotFoundError:
                console.print(f"[red]Error: Credentials file not found: {credentials_file}[/red]")
                sys.exit(1)
            except Exception as e:
                console.print(f"[red]Error reading credentials file: {e}[/red]")
                sys.exit(1)
        
        elif multiple_usernames and multiple_passwords:
            # Parse multiple usernames and passwords
            usernames = [u.strip() for u in multiple_usernames.split(',')]
            passwords = [p.strip() for p in multiple_passwords.split(',')]
            
            if len(usernames) != len(passwords):
                console.print("[red]Error: Number of usernames must match number of passwords[/red]")
                sys.exit(1)
            
            for u, p in zip(usernames, passwords):
                if not validate_username(u):
                    console.print(f"[red]Error: Invalid username format: {u}[/red]")
                    sys.exit(1)
                credentials_list.append({'username': u, 'password': p})
            
            console.print(f"[green]Using {len(credentials_list)} username/password pairs[/green]")
        
        elif multiple_usernames:
            # Multiple usernames with single password or key
            usernames = [u.strip() for u in multiple_usernames.split(',')]
            
            for u in usernames:
                if not validate_username(u):
                    console.print(f"[red]Error: Invalid username format: {u}[/red]")
                    sys.exit(1)
                
                cred = {'username': u}
                if password:
                    cred['password'] = password
                if key_file:
                    cred['key_file'] = key_file
                credentials_list.append(cred)
            
            console.print(f"[green]Using {len(credentials_list)} usernames[/green]")
        
        else:
            console.print("[red]Error: --try-multiple-credentials requires --multiple-usernames, --multiple-passwords, or --credentials-file[/red]")
            sys.exit(1)
    
    else:
        # Single credential mode (existing behavior)
        if not username:
            console.print("[red]Error: Must provide --username for single credential mode[/red]")
            sys.exit(1)
        
        if not password and not key_file and not try_all_methods:
            # Prompt user (legacy behaviour) if no stored credential available
            password = click.prompt(
                "Enter SSH password",
                hide_input=True,
                show_default=False,
                default=""
            )
            if password:
                console.print("[yellow]Password captured from prompt[/yellow]")
            else:
                console.print("[red]Error: Must provide --password, --key-file, or --try-all-methods[/red]")
                sys.exit(1)
    
    # Display configuration
    console.print(f"[green]SSH port:[/green] {port}")
    console.print(f"[green]Timeout:[/green] {timeout}s")
    console.print(f"[green]Threads:[/green] {threads}")
    
    if try_multiple_credentials:
        console.print(f"[green]Credentials:[/green] {len(credentials_list)} credential pairs")
    else:
        username_suffix = " [dim](stored)[/dim]" if used_stored_username else ""
        console.print(f"[green]Username:[/green] {username}{username_suffix}")
        if password:
            password_suffix = " [dim](stored)[/dim]" if used_stored_password else ""
            console.print(f"[yellow]Password:[/yellow] [redacted]{password_suffix}")
        if key_file:
            key_suffix = " [dim](stored)[/dim]" if used_stored_key else ""
            console.print(f"[yellow]Key file:[/yellow] {key_file}{key_suffix}")
        if try_all_methods:
            console.print("[yellow]Will try all available authentication methods[/yellow]")
    
    try:
        # Initialize SSH connector
        ssh_connector = SSHConnector(timeout=timeout)
        
        results = []
        
        if try_multiple_credentials:
            # Test multiple credentials
            console.print(f"\n[cyan]Testing multiple credentials on {len(host_list)} hosts...[/cyan]")
            results = ssh_connector.concurrent_test_multiple_credentials(
                host_list, port, credentials_list, threads
            )
        elif try_all_methods:
            # Try all authentication methods for each host
            console.print(f"\n[cyan]Testing all authentication methods on {len(host_list)} hosts...[/cyan]")
            
            for host in host_list:
                console.print(f"\n[blue]Testing host: {host}[/blue]")
                result = ssh_connector.try_multiple_auth_methods(host, port, username, password)
                results.append(result)
        else:
            # Test specific authentication method
            console.print(f"\n[cyan]Testing SSH connections to {len(host_list)} hosts...[/cyan]")
            results = ssh_connector.concurrent_test_connections(
                host_list, port, username, password, key_file, threads
            )
        
        # Display results
        console.print("\n[bold blue]SSH Authentication Results:[/bold blue]")
        
        successful_hosts = []
        failed_hosts = []
        
        for result in results:
            if result['connected']:
                successful_hosts.append(result)
                if try_multiple_credentials:
                    # Display multiple credentials results
                    cred_info = result.get('successful_credential', {})
                    username_used = cred_info.get('username', 'unknown')
                    method_used = cred_info.get('method', 'unknown')
                    console.print(f"[green]✓ {result['host']}:{result['port']} - {username_used} ({method_used})[/green]")
                else:
                    # Display single credential results
                    auth_method = result.get('auth_method', 'unknown')
                    console.print(f"[green]✓ {result['host']}:{result['port']} - {auth_method}[/green]")
            else:
                failed_hosts.append(result)
                if try_multiple_credentials:
                    attempt_count = len(result.get('attempts', []))
                    console.print(f"[red]✗ {result['host']}:{result['port']} - {result['error']} ({attempt_count} attempts)[/red]")
                else:
                    console.print(f"[red]✗ {result['host']}:{result['port']} - {result['error']}[/red]")
        
        # Summary
        summary = ssh_connector.get_connection_summary(results)
        console.print(f"\n[bold blue]Summary:[/bold blue]")
        console.print(f"[green]Successful connections:[/green] {summary['successful_connections']}")
        console.print(f"[red]Failed connections:[/red] {summary['failed_connections']}")
        console.print(f"[cyan]Success rate:[/cyan] {summary['success_rate']:.1f}%")
        
        if summary['auth_methods']:
            console.print(f"[blue]Authentication methods used:[/blue]")
            for method, count in summary['auth_methods'].items():
                console.print(f"  - {method}: {count}")
        
        console.print(f"\n[bold green]SSH authentication test completed![/bold green]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]SSH test interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error during SSH test: {e}[/red]")
        if ctx.obj.get('debug'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

@scan.command()
@click.option('--hosts', '-h', help='Comma-separated list of IP addresses/hostnames')
@click.option('--from-db', is_flag=True, help='Use hosts from database')
@click.option('--username', '-u', help='SSH username (falls back to stored credential)')
@click.option('--password', '-p', help='SSH password (falls back to stored credential)')
@click.option('--key-file', '-k', help='SSH private key file path')
@click.option('--multiple-usernames', help='Comma-separated list of usernames to try')
@click.option('--multiple-passwords', help='Comma-separated list of passwords to try')
@click.option('--credentials-file', help='File containing username:password pairs (one per line)')
@click.option('--try-multiple-credentials', is_flag=True, help='Try multiple username/password combinations')
@click.option('--port', '-P', default=22, help='SSH port (default: 22)')
@click.option('--timeout', '-T', default=8, help='Connection timeout in seconds (default: 8)')
@click.option('--store-db', is_flag=True, help='Store collected information in database')
@click.option('--output', '-o', help='Output file for detailed results')
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.pass_context
def info(ctx, hosts, from_db, username, password, key_file, multiple_usernames, multiple_passwords, credentials_file, try_multiple_credentials, port, timeout, store_db, output, format):
    """Collect system information from SSH-accessible hosts"""
    
    console.print(Panel.fit(
        Text("NetScan - System Information Collector", style="bold magenta"),
        border_style="magenta"
    ))
    
    # Validate inputs
    if not validate_port(port):
        console.print(f"[red]Error: Invalid port number: {port}[/red]")
        sys.exit(1)
    
    if not validate_timeout(timeout):
        console.print(f"[red]Error: Invalid timeout: {timeout}[/red]")
        sys.exit(1)
    
    # Validate username for single credential mode
    if username and not validate_username(username):
        console.print(f"[red]Error: Invalid username format: {username}[/red]")
        sys.exit(1)
    
    # Get host list
    host_list = []
    
    if from_db:
        console.print("[blue]Loading hosts from database...[/blue]")
        try:
            from .database.operations import db_manager
            hosts_from_db = db_manager.get_all_hosts(status='active')
            host_list = [host.ip_address for host in hosts_from_db]
            console.print(f"[green]Found {len(host_list)} active hosts in database[/green]")
        except Exception as e:
            console.print(f"[red]Error loading hosts from database: {e}[/red]")
            sys.exit(1)
    
    elif hosts:
        host_list = [host.strip() for host in hosts.split(',')]
        console.print(f"[green]Collecting info from {len(host_list)} specified hosts[/green]")
    
    else:
        console.print("[red]Error: Must specify either --hosts or --from-db[/red]")
        sys.exit(1)
    
    if not host_list:
        console.print("[yellow]No hosts to collect information from[/yellow]")
        return
    
    from .config import config_manager
    used_stored_username = False
    used_stored_password = False
    used_stored_key = False

    if not username:
        stored_username = config_manager.get_credential_value('username')
        if stored_username:
            username = stored_username
            used_stored_username = True

    if not password:
        stored_password = config_manager.get_credential_value('password')
        if stored_password:
            password = stored_password
            used_stored_password = True

    if not key_file:
        stored_key = config_manager.get_credential_value('ssh_key_path')
        if stored_key:
            key_file = stored_key
            used_stored_key = True

    credentials_list = []
    
    if try_multiple_credentials:
        # Parse multiple credentials (same logic as auth command)
        if credentials_file:
            console.print(f"[blue]Loading credentials from file: {credentials_file}[/blue]")
            try:
                with open(credentials_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if ':' in line:
                                cred_username, cred_password = line.split(':', 1)
                                credentials_list.append({
                                    'username': cred_username.strip(),
                                    'password': cred_password.strip()
                                })
                            else:
                                console.print(f"[yellow]Warning: Invalid credential format on line {line_num}: {line}[/yellow]")
                console.print(f"[green]Loaded {len(credentials_list)} credentials from file[/green]")
            except FileNotFoundError:
                console.print(f"[red]Error: Credentials file not found: {credentials_file}[/red]")
                sys.exit(1)
            except Exception as e:
                console.print(f"[red]Error reading credentials file: {e}[/red]")
                sys.exit(1)
        
        elif multiple_usernames and multiple_passwords:
            # Parse multiple usernames and passwords
            usernames = [u.strip() for u in multiple_usernames.split(',')]
            passwords = [p.strip() for p in multiple_passwords.split(',')]
            
            if len(usernames) != len(passwords):
                console.print("[red]Error: Number of usernames must match number of passwords[/red]")
                sys.exit(1)
            
            for u, p in zip(usernames, passwords):
                if not validate_username(u):
                    console.print(f"[red]Error: Invalid username format: {u}[/red]")
                    sys.exit(1)
                credentials_list.append({'username': u, 'password': p})
            
            console.print(f"[green]Using {len(credentials_list)} username/password pairs[/green]")
        
        elif multiple_usernames:
            # Multiple usernames with single password or key
            usernames = [u.strip() for u in multiple_usernames.split(',')]
            
            for u in usernames:
                if not validate_username(u):
                    console.print(f"[red]Error: Invalid username format: {u}[/red]")
                    sys.exit(1)
                
                cred = {'username': u}
                if password:
                    cred['password'] = password
                if key_file:
                    cred['key_file'] = key_file
                credentials_list.append(cred)
            
            console.print(f"[green]Using {len(credentials_list)} usernames[/green]")
        
        else:
            console.print("[red]Error: --try-multiple-credentials requires --multiple-usernames, --multiple-passwords, or --credentials-file[/red]")
            sys.exit(1)
    
    else:
        # Single credential mode (existing behavior)
        if not username:
            console.print("[red]Error: Must provide --username for single credential mode[/red]")
            sys.exit(1)
        
        if not password and not key_file:
            password = click.prompt(
                "Enter SSH password",
                hide_input=True,
                show_default=False,
                default=""
            )
            if password:
                console.print("[yellow]Password captured from prompt[/yellow]")
            else:
                console.print("[red]Error: Must provide either --password or --key-file[/red]")
                sys.exit(1)
    
    # Display configuration
    console.print(f"[green]SSH port:[/green] {port}")
    console.print(f"[green]Timeout:[/green] {timeout}s")
    console.print(f"[green]Output format:[/green] {format}")
    
    if try_multiple_credentials:
        console.print(f"[green]Credentials:[/green] {len(credentials_list)} credential pairs")
    else:
        username_suffix = " [dim](stored)[/dim]" if used_stored_username else ""
        console.print(f"[green]Username:[/green] {username}{username_suffix}")
        if password:
            password_suffix = " [dim](stored)[/dim]" if used_stored_password else ""
            console.print(f"[yellow]Password:[/yellow] [redacted]{password_suffix}")
        if key_file:
            key_suffix = " [dim](stored)[/dim]" if used_stored_key else ""
            console.print(f"[yellow]Key file:[/yellow] {key_file}{key_suffix}")

    if store_db:
        console.print("[yellow]Will store results in database[/yellow]")
    
    try:
        # Initialize SSH connector and system info collector
        ssh_connector = SSHConnector(timeout=timeout)
        info_collector = SystemInfoCollector(ssh_connector)
        
        # Collect system information
        if try_multiple_credentials:
            console.print(f"\n[cyan]Collecting system information from {len(host_list)} hosts using multiple credentials...[/cyan]")
            results = info_collector.collect_from_multiple_hosts_with_credentials(
                host_list, port, credentials_list
            )
        else:
            console.print(f"\n[cyan]Collecting system information from {len(host_list)} hosts...[/cyan]")
            results = info_collector.collect_from_multiple_hosts(
                host_list, port, username, password, key_file
            )
        
        # Display results
        console.print(f"\n[bold blue]System Information Collection Results:[/bold blue]")
        
        successful_collections = []
        partial_collections = []
        failed_collections = []
        
        for result in results:
            if result['collection_success']:
                successful_collections.append(result)
                if try_multiple_credentials:
                    cred_info = result.get('successful_credential', {})
                    username_used = cred_info.get('username', 'unknown')
                    console.print(f"[green]✓ {result['host']} - Complete system info collected using {username_used}[/green]")
                else:
                    console.print(f"[green]✓ {result['host']} - Complete system info collected[/green]")
            elif result.get('raw_outputs'):
                partial_collections.append(result)
                error_count = len(result['collection_errors'])
                if try_multiple_credentials:
                    cred_info = result.get('successful_credential', {})
                    username_used = cred_info.get('username', 'unknown')
                    console.print(f"[yellow]⚠ {result['host']} - Partial system info collected using {username_used} ({error_count} issues)[/yellow]")
                else:
                    console.print(f"[yellow]⚠ {result['host']} - Partial system info collected ({error_count} issues)[/yellow]")
            else:
                failed_collections.append(result)
                error_count = len(result['collection_errors'])
                if try_multiple_credentials:
                    attempt_count = result.get('auth_attempts', 0)
                    console.print(f"[red]✗ {result['host']} - {error_count} collection errors ({attempt_count} auth attempts)[/red]")
                else:
                    console.print(f"[red]✗ {result['host']} - {error_count} collection errors[/red]")
        
        # Summary
        console.print(f"\n[bold blue]Collection Summary:[/bold blue]")
        console.print(f"[green]Successful collections:[/green] {len(successful_collections)}")
        console.print(f"[yellow]Partial collections:[/yellow] {len(partial_collections)}")
        console.print(f"[red]Failed collections:[/red] {len(failed_collections)}")
        success_rate = (len(successful_collections) / len(results)) * 100 if results else 0
        coverage_rate = ((len(successful_collections) + len(partial_collections)) / len(results) * 100) if results else 0
        console.print(f"[cyan]Success rate:[/cyan] {success_rate:.1f}%")
        if partial_collections:
            console.print(f"[cyan]Hosts with usable partial data:[/cyan] {coverage_rate:.1f}%")
        
        collections_to_store = [res for res in results if res['collection_success'] or res.get('raw_outputs')]
        
        # Store in database if requested
        if store_db and collections_to_store:
            console.print(f"\n[blue]Storing system information in database...[/blue]")
            
            for result in collections_to_store:
                try:
                    parsed = result['parsed_info']
                    
                    # Prepare host data for database
                    host_data = {
                        'ip_address': result['host'],
                        'hostname': parsed.get('hostname', result['host']),
                        'os_info': parsed.get('os_info', 'Unknown'),
                        'kernel_version': parsed.get('kernel_version', 'Unknown'),
                        'status': 'active'
                    }
                    
                    # Add memory and CPU info if available
                    if 'memory' in parsed:
                        mem = parsed['memory']
                        host_data['memory_total'] = mem['total_mb']
                        host_data['memory_used'] = mem['used_mb']
                    
                    if 'cpu' in parsed:
                        cpu = parsed['cpu']
                        host_data['cpu_info'] = cpu['model']
                    
                    if 'uptime' in parsed:
                        uptime = parsed['uptime']
                        host_data['uptime'] = uptime['raw']
                    
                    if 'disk' in parsed:
                        import json
                        host_data['disk_usage'] = json.dumps(parsed['disk'])

                    cred_info = result.get('successful_credential', {})
                    if cred_info:
                        host_data['working_username'] = cred_info.get('username')
                        host_data['auth_method'] = cred_info.get('method')
                    if result.get('auth_attempts') is not None:
                        host_data['auth_attempts'] = result.get('auth_attempts')
                    
                    # Create or update host in database
                    from .database.operations import db_manager
                    db_manager.create_host(host_data)
                    
                    if not result['collection_success']:
                        console.print(f"[yellow]Stored partial data for {result['host']} (some fields unavailable)[/yellow]")
                    
                except Exception as e:
                    console.print(f"[red]Error storing info for {result['host']}: {e}[/red]")
            
            console.print(f"[green]✓ System information stored in database[/green]")
        
        # Output detailed results
        if output:
            console.print(f"\n[blue]Writing detailed results to {output}...[/blue]")
            try:
                with open(output, 'w') as f:
                    if format == 'json':
                        import json
                        json.dump(results, f, indent=2, default=str)
                    else:
                        for result in results:
                            f.write(info_collector.format_system_info(result))
                            f.write("\n\n")
                
                console.print(f"[green]✓ Results written to {output}[/green]")
            except Exception as e:
                console.print(f"[red]Error writing to file: {e}[/red]")
        
        # Display sample system information
        sample_source = successful_collections or partial_collections
        if sample_source:
            console.print(f"\n[bold blue]Sample System Information:[/bold blue]")
            sample = sample_source[0]
            console.print(info_collector.format_system_info(sample))
        
        console.print(f"\n[bold green]System information collection completed![/bold green]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Information collection interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error during information collection: {e}[/red]")
        if ctx.obj.get('debug'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

@scan.command()
@click.option('--range', '-r', required=True, help='IP range to scan (e.g., 192.168.1.0/24) or comma-separated IPs')
@click.option('--username', '-u', help='SSH username')
@click.option('--password', '-p', help='SSH password')
@click.option('--key-file', '-k', help='SSH private key file path')
@click.option('--multiple-usernames', help='Comma-separated list of usernames to try')
@click.option('--multiple-passwords', help='Comma-separated list of passwords to try')
@click.option('--credentials-file', help='File containing username:password pairs (one per line)')
@click.option('--port', '-P', default=22, help='SSH port (default: 22)')
@click.option('--timeout', '-T', default=5, help='Connection timeout in seconds (default: 5)')
@click.option('--threads', '-t', default=10, help='Number of concurrent threads (default: 10)')
@click.option('--no-nmap', is_flag=True, help='Skip nmap scan and use socket scan only')
@click.option('--store-db', is_flag=True, default=True, help='Store results in database (default: True)')
@click.option('--output', '-o', help='Output file for detailed results')
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='json', help='Output format (default: json)')
@click.pass_context
def full(ctx, range, username, password, key_file, multiple_usernames, multiple_passwords, credentials_file, port, timeout, threads, no_nmap, store_db, output, format):
    """Complete network analysis: Discovery → Authentication → Information Collection → Database Storage"""
    
    console.print(Panel.fit(
        Text("NetScan - Comprehensive Network Analysis", style="bold cyan"),
        border_style="cyan"
    ))
    
    # Validate inputs
    if not validate_port(port):
        console.print(f"[red]Error: Invalid port number: {port}[/red]")
        sys.exit(1)
    
    if not validate_timeout(timeout):
        console.print(f"[red]Error: Invalid timeout: {timeout}[/red]")
        sys.exit(1)
    
    if not validate_threads(threads):
        console.print(f"[red]Error: Invalid thread count: {threads}[/red]")
        sys.exit(1)
    
    # Parse and validate credentials (reusing logic from auth command)
    credentials_list = []
    
    if credentials_file:
        console.print(f"[blue]Loading credentials from file: {credentials_file}[/blue]")
        try:
            with open(credentials_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if ':' in line:
                            cred_username, cred_password = line.split(':', 1)
                            credentials_list.append({
                                'username': cred_username.strip(),
                                'password': cred_password.strip()
                            })
                        else:
                            console.print(f"[yellow]Warning: Invalid credential format on line {line_num}: {line}[/yellow]")
            console.print(f"[green]Loaded {len(credentials_list)} credentials from file[/green]")
        except FileNotFoundError:
            console.print(f"[red]Error: Credentials file not found: {credentials_file}[/red]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]Error reading credentials file: {e}[/red]")
            sys.exit(1)
    
    elif multiple_usernames and multiple_passwords:
        # Parse multiple usernames and passwords
        usernames = [u.strip() for u in multiple_usernames.split(',')]
        passwords = [p.strip() for p in multiple_passwords.split(',')]
        
        if len(usernames) != len(passwords):
            console.print("[red]Error: Number of usernames must match number of passwords[/red]")
            sys.exit(1)
        
        for u, p in zip(usernames, passwords):
            if not validate_username(u):
                console.print(f"[red]Error: Invalid username format: {u}[/red]")
                sys.exit(1)
            credentials_list.append({'username': u, 'password': p})
        
        console.print(f"[green]Using {len(credentials_list)} username/password pairs[/green]")
    
    elif multiple_usernames:
        # Multiple usernames with single password or key
        usernames = [u.strip() for u in multiple_usernames.split(',')]
        
        for u in usernames:
            if not validate_username(u):
                console.print(f"[red]Error: Invalid username format: {u}[/red]")
                sys.exit(1)
            
            cred = {'username': u}
            if password:
                cred['password'] = password
            if key_file:
                cred['key_file'] = key_file
            credentials_list.append(cred)
        
        console.print(f"[green]Using {len(credentials_list)} usernames[/green]")
    
    elif username:
        # Single credential
        if not validate_username(username):
            console.print(f"[red]Error: Invalid username format: {username}[/red]")
            sys.exit(1)
        
        cred = {'username': username}
        if password:
            cred['password'] = password
        if key_file:
            cred['key_file'] = key_file
        credentials_list.append(cred)
        
        console.print(f"[green]Using single credential: {username}[/green]")
    
    else:
        console.print("[red]Error: Must provide credentials via --username, --multiple-usernames, or --credentials-file[/red]")
        sys.exit(1)
    
    # Display configuration
    console.print(f"[green]IP Range:[/green] {range}")
    console.print(f"[green]SSH Port:[/green] {port}")
    console.print(f"[green]Timeout:[/green] {timeout}s")
    console.print(f"[green]Threads:[/green] {threads}")
    console.print(f"[green]Credentials:[/green] {len(credentials_list)} credential pairs")
    console.print(f"[green]Use nmap:[/green] {not no_nmap}")
    console.print(f"[green]Store in DB:[/green] {store_db}")
    
    try:
        # Initialize comprehensive scanner
        comprehensive_scanner = ComprehensiveScanner(timeout=timeout, threads=threads)
        
        # Perform comprehensive scan
        results = comprehensive_scanner.comprehensive_scan(
            ip_range=range,
            port=port,
            credentials=credentials_list,
            store_db=store_db,
            use_nmap=not no_nmap
        )
        
        # Output detailed results if requested
        if output:
            console.print(f"\n[blue]Writing detailed results to {output}...[/blue]")
            try:
                with open(output, 'w') as f:
                    if format == 'json':
                        import json
                        json.dump(results, f, indent=2, default=str)
                    else:
                        # Text format summary
                        f.write("NetScan Comprehensive Scan Results\n")
                        f.write("=" * 50 + "\n\n")
                        
                        # Network Discovery
                        net = results['network_discovery']
                        f.write(f"Network Discovery:\n")
                        f.write(f"  SSH hosts found: {net['ssh_hosts_found']}\n\n")
                        
                        # Authentication
                        auth = results['authentication']
                        f.write(f"Authentication:\n")
                        f.write(f"  Hosts tested: {auth['hosts_tested']}\n")
                        f.write(f"  Successful auths: {auth['successful_auths']}\n")
                        f.write(f"  Failed auths: {auth['failed_auths']}\n\n")
                        
                        # System Info
                        info = results['system_info']
                        f.write(f"System Information:\n")
                        f.write(f"  Hosts processed: {info['hosts_collected']}\n")
                        f.write(f"  Successful collections: {info['successful_collections']}\n")
                        f.write(f"  Failed collections: {info['failed_collections']}\n\n")
                        
                        # Database
                        db = results['database_storage']
                        f.write(f"Database Storage:\n")
                        f.write(f"  Hosts stored: {db['hosts_stored']}\n")
                        f.write(f"  Storage errors: {len(db['storage_errors'])}\n\n")
                        
                        # Timing
                        duration = results['scan_end_time'] - results['scan_start_time']
                        f.write(f"Scan Duration: {duration:.1f} seconds\n")
                
                console.print(f"[green]✓ Results written to {output}[/green]")
            except Exception as e:
                console.print(f"[red]Error writing to file: {e}[/red]")
        
        console.print(f"\n[bold green]Comprehensive scan completed successfully![/bold green]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Comprehensive scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error during comprehensive scan: {e}[/red]")
        if ctx.obj.get('debug'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

@cli.group()
@click.pass_context
def report(ctx):
    """Report generation and viewing"""
    pass

@report.command()
@click.option('--filter', '-f', 
              help='Filter results (e.g., "os=ubuntu", "status=active")')
@click.option('--format', '-F', 
              type=click.Choice(['table', 'json', 'csv', 'text']), 
              default='table',
              help='Output format (default: table)')
@click.option('--output', '-o', 
              help='Output file path')
@click.option('--sort', '-s', 
              help='Sort by field (e.g., ip_address, hostname, last_scan)')
@click.option('--limit', '-l', type=int, 
              help='Limit number of results')
@click.pass_context
def hosts(ctx, filter, format, output, sort, limit):
    """List discovered hosts"""
    
    console.print(Panel.fit(
        Text("NetScan - Host Report", style="bold magenta"),
        border_style="magenta"
    ))
    
    from .reporting.formatter import ReportFormatter
    
    try:
        # Get hosts from database
        from .database.operations import db_manager
        hosts = db_manager.get_all_hosts()
        
        if not hosts:
            console.print("[yellow]No hosts found in database. Run a scan first.[/yellow]")
            return
        
        # Apply filters
        if filter:
            console.print(f"[green]Filter:[/green] {filter}")
            hosts = apply_host_filter(hosts, filter)
        
        # Apply sorting
        if sort:
            console.print(f"[green]Sort:[/green] {sort}")
            hosts = sort_hosts(hosts, sort)
        
        # Apply limit
        if limit:
            console.print(f"[green]Limit:[/green] {limit}")
            hosts = hosts[:limit]
        
        console.print(f"[green]Format:[/green] {format}")
        console.print(f"[green]Total hosts:[/green] {len(hosts)}")
        
        # Format output
        formatter = ReportFormatter()
        
        if format == 'table':
            table = formatter.format_hosts_table(hosts)
            console.print(table)
        elif format == 'json':
            json_output = formatter.format_hosts_json(hosts)
            if output:
                with open(output, 'w') as f:
                    f.write(json_output)
                console.print(f"[green]✓ JSON output written to {output}[/green]")
            else:
                console.print(json_output)
        elif format == 'csv':
            csv_output = formatter.format_hosts_csv(hosts)
            if output:
                with open(output, 'w') as f:
                    f.write(csv_output)
                console.print(f"[green]✓ CSV output written to {output}[/green]")
            else:
                console.print(csv_output)
        elif format == 'text':
            text_output = formatter.format_hosts_text(hosts)
            if output:
                with open(output, 'w') as f:
                    f.write(text_output)
                console.print(f"[green]✓ Text output written to {output}[/green]")
            else:
                console.print(text_output)
        
    except Exception as e:
        console.print(f"[red]Error generating host report: {e}[/red]")
        if ctx.obj.get('debug'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

@report.command()
@click.option('--output', '-o', 
              help='Output file path')
@click.pass_context
def summary(ctx, output):
    """Display summary statistics"""
    
    console.print(Panel.fit(
        Text("NetScan - Summary Report", style="bold cyan"),
        border_style="cyan"
    ))
    
    from .reporting.formatter import ReportFormatter
    
    try:
        # Get hosts and statistics
        from .database.operations import db_manager
        hosts = db_manager.get_all_hosts()
        stats = db_manager.get_host_statistics()
        
        if not hosts:
            console.print("[yellow]No hosts found in database. Run a scan first.[/yellow]")
            return
        
        # Format and display summary
        formatter = ReportFormatter()
        
        # Display statistics panel
        stats_panel = formatter.format_statistics_panel(stats)
        console.print(stats_panel)
        
        # Create comprehensive summary
        summary_text = formatter.create_summary_report(hosts, stats)
        
        if output:
            with open(output, 'w') as f:
                f.write(summary_text)
            console.print(f"\n[green]✓ Summary report written to {output}[/green]")
        else:
            console.print(f"\n[bold blue]Detailed Summary:[/bold blue]")
            console.print(summary_text)
        
    except Exception as e:
        console.print(f"[red]Error generating summary report: {e}[/red]")
        if ctx.obj.get('debug'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

@report.command()
@click.option('--format', '-f', 
              type=click.Choice(['json', 'csv', 'xml', 'txt', 'sql']), 
              default='json',
              help='Export format (default: json)')
@click.option('--output', '-o', required=True,
              help='Output file path')
@click.option('--filter', '-F', 
              help='Filter results (e.g., "os=ubuntu", "status=active")')
@click.option('--include-history', is_flag=True,
              help='Include scan history in export')
@click.pass_context
def export(ctx, format, output, filter, include_history):
    """Export host data to file"""
    
    console.print(Panel.fit(
        Text("NetScan - Data Export", style="bold yellow"),
        border_style="yellow"
    ))
    
    from .reporting.exporter import ReportExporter
    
    try:
        # Get hosts from database
        from .database.operations import db_manager
        hosts = db_manager.get_all_hosts()
        
        if not hosts:
            console.print("[yellow]No hosts found in database. Run a scan first.[/yellow]")
            return
        
        # Apply filters
        if filter:
            console.print(f"[green]Filter:[/green] {filter}")
            hosts = apply_host_filter(hosts, filter)
        
        console.print(f"[green]Format:[/green] {format}")
        console.print(f"[green]Output:[/green] {output}")
        console.print(f"[green]Total hosts to export:[/green] {len(hosts)}")
        
        # Export data
        exporter = ReportExporter()
        
        if format == 'json':
            success = exporter.export_hosts_json(hosts, output)
        elif format == 'csv':
            success = exporter.export_hosts_csv(hosts, output)
        elif format == 'xml':
            success = exporter.export_hosts_xml(hosts, output)
        elif format == 'txt':
            success = exporter.export_hosts_text(hosts, output)
        elif format == 'sql':
            success = exporter.export_hosts_sql(hosts, output)
        
        if success:
            console.print(f"[green]✓ Data exported successfully to {output}[/green]")
            
            # Export scan history if requested
            if include_history:
                history = db_manager.get_scan_history()
                if history:
                    history_file = output.replace(f'.{format}', f'_history.{format}')
                    history_success = exporter.export_scan_history(history, history_file, format)
                    if history_success:
                        console.print(f"[green]✓ Scan history exported to {history_file}[/green]")
        else:
            console.print(f"[red]Failed to export data[/red]")
            sys.exit(1)
        
    except Exception as e:
        console.print(f"[red]Error exporting data: {e}[/red]")
        if ctx.obj.get('debug'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

@report.command()
@click.option('--host-id', '-h', type=int,
              help='Filter by specific host ID')
@click.option('--scan-type', '-t', 
              help='Filter by scan type (e.g., network, auth, info)')
@click.option('--limit', '-l', type=int, default=50,
              help='Limit number of results (default: 50)')
@click.option('--format', '-f', 
              type=click.Choice(['table', 'json', 'csv']), 
              default='table',
              help='Output format (default: table)')
@click.option('--output', '-o', 
              help='Output file path')
@click.pass_context
def history(ctx, host_id, scan_type, limit, format, output):
    """Display scan history"""
    
    console.print(Panel.fit(
        Text("NetScan - Scan History", style="bold blue"),
        border_style="blue"
    ))
    
    from .reporting.formatter import ReportFormatter
    
    try:
        # Get scan history from database
        from .database.operations import db_manager
        history = db_manager.get_scan_history(host_id=host_id, scan_type=scan_type, limit=limit)
        
        if not history:
            console.print("[yellow]No scan history found.[/yellow]")
            return
        
        console.print(f"[green]Total history records:[/green] {len(history)}")
        
        if host_id:
            console.print(f"[green]Host ID filter:[/green] {host_id}")
        if scan_type:
            console.print(f"[green]Scan type filter:[/green] {scan_type}")
        
        # Format output
        formatter = ReportFormatter()
        
        if format == 'table':
            table = formatter.format_scan_history_table(history)
            console.print(table)
        elif format == 'json':
            import json
            history_data = [h.to_dict() for h in history]
            json_output = json.dumps(history_data, indent=2, default=str)
            if output:
                with open(output, 'w') as f:
                    f.write(json_output)
                console.print(f"[green]✓ JSON output written to {output}[/green]")
            else:
                console.print(json_output)
        elif format == 'csv':
            import csv
            import io
            output_stream = io.StringIO()
            writer = csv.writer(output_stream)
            
            # Write header
            writer.writerow(['ID', 'Host_ID', 'Scan_Type', 'Result', 'Error_Message', 'Scan_Duration', 'Timestamp'])
            
            # Write data
            for h in history:
                writer.writerow([
                    h.id, h.host_id, h.scan_type or '', h.result or '', 
                    h.error_message or '', h.scan_duration or '', 
                    h.timestamp.isoformat() if h.timestamp else ''
                ])
            
            csv_output = output_stream.getvalue()
            if output:
                with open(output, 'w') as f:
                    f.write(csv_output)
                console.print(f"[green]✓ CSV output written to {output}[/green]")
            else:
                console.print(csv_output)
        
    except Exception as e:
        console.print(f"[red]Error generating history report: {e}[/red]")
        if ctx.obj.get('debug'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

def apply_host_filter(hosts, filter_str):
    """Apply filter to host list"""
    if not filter_str:
        return hosts
    
    filtered_hosts = []
    
    # Parse filter (simple key=value format)
    try:
        key, value = filter_str.split('=', 1)
        key = key.strip()
        value = value.strip()
        
        for host in hosts:
            if key == 'status' and host.status == value:
                filtered_hosts.append(host)
            elif key == 'os' and host.os_info and value.lower() in host.os_info.lower():
                filtered_hosts.append(host)
            elif key == 'ip' and value in host.ip_address:
                filtered_hosts.append(host)
            elif key == 'hostname' and host.hostname and value.lower() in host.hostname.lower():
                filtered_hosts.append(host)
            elif key == 'port' and host.ssh_port == int(value):
                filtered_hosts.append(host)
    
    except ValueError:
        console.print(f"[red]Invalid filter format: {filter_str}. Use key=value format.[/red]")
        return hosts
    
    return filtered_hosts

def sort_hosts(hosts, sort_field):
    """Sort hosts by specified field"""
    if sort_field == 'ip_address':
        return sorted(hosts, key=lambda h: h.ip_address)
    elif sort_field == 'hostname':
        return sorted(hosts, key=lambda h: h.hostname or '')
    elif sort_field == 'last_scan':
        return sorted(hosts, key=lambda h: h.last_scan or datetime.min, reverse=True)
    elif sort_field == 'status':
        return sorted(hosts, key=lambda h: h.status)
    elif sort_field == 'port':
        return sorted(hosts, key=lambda h: h.ssh_port)
    else:
        console.print(f"[yellow]Unknown sort field: {sort_field}. Using default order.[/yellow]")
        return hosts

@cli.group()
@click.pass_context
def config(ctx):
    """Configuration management"""
    pass

@config.command()
@click.argument('key', required=False)
@click.argument('value', required=False)
@click.option('--set-username', help='Set default SSH username')
@click.option('--set-password', help='Set default SSH password')
@click.option('--set-port', type=int, help='Set default SSH port')
@click.option('--set-threads', type=int, help='Set default number of threads')
@click.option('--set-timeout', type=int, help='Set default timeout')
@click.option('--set-auth-timeout', type=int, help='Set SSH authentication timeout')
@click.option('--set-preferred-auth', type=click.Choice(['key', 'password', 'agent']), help='Set preferred authentication method')
@click.option('--set-additional-ports', help='Set additional ports to scan (comma-separated list)')
@click.option('--set-log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']), help='Set logging level')
@click.pass_context
def set(ctx, key, value, set_username, set_password, set_port, set_threads, set_timeout, set_auth_timeout, set_preferred_auth, set_additional_ports, set_log_level):
    """Set configuration values"""
    
    console.print(Panel.fit(
        Text("NetScan - Configuration", style="bold blue"),
        border_style="blue"
    ))
    
    from .config import config_manager
    
    try:
        changes_made = False
        key = key.strip() if key else None
        value = value.strip() if isinstance(value, str) else value

        def resolve_alias(config_key: str) -> str:
            aliases = {
                'scanning.threads': 'scanning.default_threads',
                'scanning.timeout': 'scanning.default_timeout',
                'scanning.port': 'scanning.default_port',
                'scanning.retries': 'scanning.max_retries',
                'scanning.additional': 'scanning.additional_ports',
                'scanning.extra_ports': 'scanning.additional_ports'
            }
            return aliases.get(config_key.lower(), config_key)

        def coerce(raw_value: str, current_value=None):
            if raw_value is None:
                return None
            text = raw_value.strip()
            if current_value is not None:
                if isinstance(current_value, bool):
                    return text.lower() in ('1', 'true', 'yes', 'on')
                if isinstance(current_value, int):
                    try:
                        return int(text)
                    except ValueError:
                        pass
                if isinstance(current_value, float):
                    try:
                        return float(text)
                    except ValueError:
                        pass
            lowered = text.lower()
            if lowered in ('true', 'false'):
                return lowered == 'true'
            try:
                return int(text)
            except ValueError:
                try:
                    return float(text)
                except ValueError:
                    return text

        # Handle direct key/value updates (dot notation)
        if key:
            if value is None:
                console.print(f"[red]Error: Missing value for configuration key '{key}'[/red]")
                sys.exit(1)

            normalized_key = resolve_alias(key)
            current_value = config_manager.get_value(normalized_key)
            new_value = coerce(value, current_value)

            if '.' not in normalized_key:
                console.print(f"[red]Error: Configuration key '{normalized_key}' must use section.key format[/red]")
                sys.exit(1)

            section, cfg_key = normalized_key.split('.', 1)
            config_manager.set(section, cfg_key, new_value)
            console.print(f"[green]✓ {normalized_key} set:[/green] {new_value}")
            changes_made = True
        
        # Handle credentials separately
        if set_username:
            if config_manager.set_credential('username', set_username):
                console.print(f"[green]✓ Username set:[/green] {set_username}")
                changes_made = True
            else:
                console.print("[red]Error setting username[/red]")
        
        if set_password:
            if config_manager.set_credential('password', set_password):
                console.print("[green]✓ Password set:[/green] [redacted]")
                changes_made = True
            else:
                console.print("[red]Error setting password[/red]")
        
        # Handle configuration settings
        if set_port:
            if 1 <= set_port <= 65535:
                config_manager.set('scanning', 'default_port', set_port)
                console.print(f"[green]✓ Default port set:[/green] {set_port}")
                changes_made = True
            else:
                console.print("[red]Error: Port must be between 1 and 65535[/red]")
        
        if set_threads:
            if 1 <= set_threads <= 100:
                config_manager.set('scanning', 'default_threads', set_threads)
                console.print(f"[green]✓ Default threads set:[/green] {set_threads}")
                changes_made = True
            else:
                console.print("[red]Error: Threads must be between 1 and 100[/red]")
        
        if set_timeout:
            if 1 <= set_timeout <= 300:
                config_manager.set('scanning', 'default_timeout', set_timeout)
                console.print(f"[green]✓ Default timeout set:[/green] {set_timeout}")
                changes_made = True
            else:
                console.print("[red]Error: Timeout must be between 1 and 300 seconds[/red]")
        
        if set_auth_timeout:
            if 1 <= set_auth_timeout <= 60:
                config_manager.set('ssh', 'auth_timeout', set_auth_timeout)
                console.print(f"[green]✓ SSH authentication timeout set:[/green] {set_auth_timeout}")
                changes_made = True
            else:
                console.print("[red]Error: Auth timeout must be between 1 and 60 seconds[/red]")
        
        if set_preferred_auth:
            config_manager.set('ssh', 'preferred_auth', set_preferred_auth)
            console.print(f"[green]✓ Preferred authentication method set:[/green] {set_preferred_auth}")
            changes_made = True

        if set_additional_ports is not None:
            ports = config_manager.set_additional_ports(set_additional_ports)
            if ports:
                console.print(f"[green]✓ Additional ports set:[/green] {', '.join(str(p) for p in ports)}")
            else:
                console.print("[yellow]Additional ports cleared[/yellow]")
            changes_made = True
        
        if set_log_level:
            config_manager.set('logging', 'level', set_log_level)
            console.print(f"[green]✓ Log level set:[/green] {set_log_level}")
            changes_made = True
        
        if changes_made:
            # Save configuration to file
            if config_manager.save_config():
                console.print("\n[green]✓ Configuration saved successfully[/green]")
            else:
                console.print("\n[yellow]Configuration updated but file save failed[/yellow]")
        else:
            console.print("[yellow]No configuration changes specified[/yellow]")
            console.print("Use --help to see available options")
    
    except Exception as e:
        console.print(f"[red]Error updating configuration: {e}[/red]")
        if ctx.obj.get('debug'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

@config.command(name='set-credential')
@click.argument('credential_type')
@click.argument('value', required=False)
@click.option('--no-encrypt', is_flag=True, help='Store credential without encoding')
@click.pass_context
def set_credential_command(ctx, credential_type, value, no_encrypt):
    """Store a credential such as username or password"""

    console.print(Panel.fit(
        Text("NetScan - Credential Setup", style="bold cyan"),
        border_style="cyan"
    ))

    from .config import config_manager

    try:
        cred_key = credential_type.strip().lower()
        if not cred_key:
            console.print("[red]Error: Credential type is required[/red]")
            sys.exit(1)

        provided_value = value
        if provided_value is None:
            prompt_label = cred_key.replace('_', ' ')
            if cred_key in ('password', 'passphrase'):
                provided_value = click.prompt(
                    f"Enter {prompt_label}",
                    hide_input=True,
                    confirmation_prompt=True,
                    show_default=False
                )
            else:
                provided_value = click.prompt(
                    f"Enter {prompt_label}",
                    show_default=False
                )

        if not provided_value:
            console.print("[yellow]No credential provided. Nothing changed.[/yellow]")
            return

        if config_manager.set_credential(cred_key, provided_value, encrypt=not no_encrypt):
            suffix = " (stored without encoding)" if no_encrypt else ""
            label = cred_key.replace('_', ' ').title()
            display_value = provided_value if cred_key != 'password' else '[redacted]'
            console.print(f"[green]✓ {label} stored:[/green] {display_value}{suffix}")
        else:
            console.print(f"[red]Error storing credential '{cred_key}'[/red]")

    except click.Abort:
        console.print("\n[yellow]Credential entry cancelled[/yellow]")
    except Exception as e:
        console.print(f"[red]Error storing credential: {e}[/red]")
        if ctx.obj.get('debug'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

@config.command()
@click.option('--section', help='Show specific configuration section')
@click.option('--credentials', is_flag=True, help='Show stored credentials (metadata only)')
@click.pass_context
def show(ctx, section, credentials):
    """Show current configuration"""
    
    console.print(Panel.fit(
        Text("NetScan - Current Configuration", style="bold blue"),
        border_style="blue"
    ))
    
    from .config import config_manager
    from rich.table import Table
    
    try:
        if credentials:
            # Show stored credentials
            creds = config_manager.list_credentials()
            
            if creds:
                console.print("\n[bold cyan]Stored Credentials:[/bold cyan]")
                cred_table = Table(show_header=True, header_style="bold magenta")
                cred_table.add_column("Type", style="cyan")
                cred_table.add_column("Encrypted", style="yellow")
                cred_table.add_column("Last Updated", style="green")
                
                for cred_type, metadata in creds.items():
                    cred_table.add_row(
                        cred_type,
                        "Yes" if metadata['encrypted'] else "No",
                        metadata['updated']
                    )
                
                console.print(cred_table)
            else:
                console.print("\n[yellow]No stored credentials found[/yellow]")
        
        elif section:
            # Show specific section
            section_config = config_manager.get_section(section)
            
            if section_config:
                console.print(f"\n[bold cyan]Configuration Section: {section}[/bold cyan]")
                section_table = Table(show_header=True, header_style="bold magenta")
                section_table.add_column("Key", style="cyan")
                section_table.add_column("Value", style="green")
                
                for key, value in section_config.items():
                    section_table.add_row(key, str(value))
                
                console.print(section_table)
            else:
                console.print(f"[red]Configuration section '{section}' not found[/red]")
        
        else:
            # Show all configuration
            console.print("\n[bold cyan]Current Configuration:[/bold cyan]")
            
            for section_name, section_config in config_manager.config.items():
                console.print(f"\n[bold yellow]{section_name.upper()}:[/bold yellow]")
                
                config_table = Table(show_header=True, header_style="bold magenta")
                config_table.add_column("Key", style="cyan")
                config_table.add_column("Value", style="green")
                
                for key, value in section_config.items():
                    config_table.add_row(key, str(value))
                
                console.print(config_table)
            
            # Show validation errors if any
            errors = config_manager.validate_config()
            if errors:
                console.print("\n[bold red]Configuration Validation Errors:[/bold red]")
                for section_name, section_errors in errors.items():
                    console.print(f"[red]{section_name}:[/red]")
                    for error in section_errors:
                        console.print(f"  - {error}")
    
    except Exception as e:
        console.print(f"[red]Error showing configuration: {e}[/red]")
        if ctx.obj.get('debug'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

@config.command()
@click.option('--file', '-f', required=True, help='Configuration file path')
@click.pass_context
def export(ctx, file):
    """Export configuration to file"""
    
    console.print(Panel.fit(
        Text("NetScan - Export Configuration", style="bold green"),
        border_style="green"
    ))
    
    from .config import config_manager
    
    try:
        if config_manager.export_config(file):
            console.print(f"[green]✓ Configuration exported to {file}[/green]")
        else:
            console.print(f"[red]Failed to export configuration to {file}[/red]")
            sys.exit(1)
    
    except Exception as e:
        console.print(f"[red]Error exporting configuration: {e}[/red]")
        if ctx.obj.get('debug'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

@config.command()
@click.option('--file', '-f', required=True, help='Configuration file path')
@click.pass_context
def import_config(ctx, file):
    """Import configuration from file"""
    
    console.print(Panel.fit(
        Text("NetScan - Import Configuration", style="bold yellow"),
        border_style="yellow"
    ))
    
    from .config import config_manager
    
    try:
        if config_manager.import_config(file):
            console.print(f"[green]✓ Configuration imported from {file}[/green]")
        else:
            console.print(f"[red]Failed to import configuration from {file}[/red]")
            sys.exit(1)
    
    except Exception as e:
        console.print(f"[red]Error importing configuration: {e}[/red]")
        if ctx.obj.get('debug'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

@config.command()
@click.confirmation_option(prompt='Are you sure you want to reset configuration to defaults?')
@click.pass_context
def reset(ctx):
    """Reset configuration to defaults"""
    
    console.print(Panel.fit(
        Text("NetScan - Reset Configuration", style="bold red"),
        border_style="red"
    ))
    
    from .config import config_manager
    
    try:
        config_manager.reset_to_defaults()
        console.print("[green]✓ Configuration reset to defaults[/green]")
    
    except Exception as e:
        console.print(f"[red]Error resetting configuration: {e}[/red]")
        if ctx.obj.get('debug'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

@config.command()
@click.option('--interactive', '-i', is_flag=True, help='Interactive credential setup')
@click.pass_context
def credentials(ctx, interactive):
    """Manage stored credentials"""
    
    console.print(Panel.fit(
        Text("NetScan - Credential Management", style="bold cyan"),
        border_style="cyan"
    ))
    
    from .config import config_manager
    
    try:
        if interactive:
            # Interactive credential setup
            console.print("[bold cyan]Interactive Credential Setup[/bold cyan]")
            console.print("Press Enter to skip any credential you don't want to set.")
            
            # Username
            current_username = config_manager.get_credential_value('username')
            if current_username:
                console.print(f"[dim]Current username: {current_username}[/dim]")
            
            username = input("Enter default SSH username: ").strip()
            if username:
                config_manager.set_credential('username', username)
                console.print("[green]✓ Username stored[/green]")
            
            # Password
            current_password = config_manager.get_credential_value('password')
            if current_password:
                console.print("[dim]Current password: [redacted][/dim]")
            
            password = config_manager.prompt_for_credential('password', 'Enter default SSH password: ')
            if password:
                console.print("[green]✓ Password stored[/green]")
            
            # SSH Key Path
            current_key = config_manager.get_credential_value('ssh_key_path')
            if current_key:
                console.print(f"[dim]Current SSH key path: {current_key}[/dim]")
            
            key_path = input("Enter SSH private key path: ").strip()
            if key_path:
                config_manager.set_credential('ssh_key_path', key_path)
                console.print("[green]✓ SSH key path stored[/green]")
        
        else:
            # Show current credentials
            creds = config_manager.list_credentials()
            
            if creds:
                console.print("\n[bold cyan]Stored Credentials:[/bold cyan]")
                from rich.table import Table
                
                cred_table = Table(show_header=True, header_style="bold magenta")
                cred_table.add_column("Type", style="cyan")
                cred_table.add_column("Encrypted", style="yellow")
                cred_table.add_column("Last Updated", style="green")
                
                for cred_type, metadata in creds.items():
                    cred_table.add_row(
                        cred_type,
                        "Yes" if metadata['encrypted'] else "No",
                        metadata['updated']
                    )
                
                console.print(cred_table)
                console.print("\n[dim]Use --interactive to update credentials[/dim]")
            else:
                console.print("[yellow]No stored credentials found[/yellow]")
                console.print("Use --interactive to set up credentials")
    
    except Exception as e:
        console.print(f"[red]Error managing credentials: {e}[/red]")
        if ctx.obj.get('debug'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

@cli.group()
@click.pass_context
def database(ctx):
    """Database management operations"""
    pass

@database.command()
@click.pass_context
def init(ctx):
    """Initialize database"""
    
    console.print(Panel.fit(
        Text("NetScan - Database Initialization", style="bold red"),
        border_style="red"
    ))
    
    try:
        # Initialize database
        from .database.operations import db_manager
        db_manager.init_database()
        console.print("[green]✓ Database initialized successfully[/green]")
        console.print(f"[green]Database path:[/green] {db_manager.database_path}")
        
        # Show statistics
        stats = db_manager.get_host_statistics()
        console.print(f"[blue]Total hosts:[/blue] {stats['total_hosts']}")
        
    except Exception as e:
        console.print(f"[red]Error initializing database: {e}[/red]")
        sys.exit(1)

@database.command()
@click.option('--file', '-f', required=True, help='Backup file path')
@click.pass_context
def backup(ctx, file):
    """Backup database"""
    
    console.print(f"[green]Backing up database to:[/green] {file}")
    
    # TODO: Implement database backup
    console.print("[yellow]Database backup will be implemented in Phase 4[/yellow]")

@database.command()
@click.option('--file', '-f', required=True, help='Restore file path')
@click.pass_context
def restore(ctx, file):
    """Restore database"""
    
    console.print(f"[green]Restoring database from:[/green] {file}")
    
    # TODO: Implement database restore
    console.print("[yellow]Database restore will be implemented in Phase 4[/yellow]")

if __name__ == '__main__':
    cli() 