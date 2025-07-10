#!/usr/bin/env python3
"""
NetScan - SSH Network Scanner
Main CLI entry point using Click
"""

import click
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
import os
import sys
from datetime import datetime
from .database.operations import db_manager
from .scanner.network import NetworkScanner
from .scanner.ssh import SSHConnector
from .scanner.collector import SystemInfoCollector
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
              help='SSH password (can be set in config)')
@click.option('--port', '-P', default=22, 
              help='SSH port (default: 22)')
@click.option('--threads', '-t', default=10, 
              help='Number of concurrent threads (default: 10)')
@click.option('--timeout', '-T', default=5, 
              help='Connection timeout in seconds (default: 5)')
@click.option('--no-nmap', is_flag=True, 
              help='Skip nmap scan and use socket scan only')
@click.pass_context
def network(ctx, range, username, password, port, threads, timeout, no_nmap):
    """Scan network range for SSH-enabled hosts"""
    
    # Welcome message
    console.print(Panel.fit(
        Text("NetScan - Network Scanner", style="bold cyan"),
        border_style="cyan"
    ))
    
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
    
    # Check for username/password (optional for network scan)
    if username and not validate_username(username):
        console.print(f"[red]Error: Invalid username format: {username}[/red]")
        sys.exit(1)
    
    console.print(f"[green]Scanning range:[/green] {range}")
    console.print(f"[green]SSH port:[/green] {port}")
    console.print(f"[green]Threads:[/green] {threads}")
    console.print(f"[green]Timeout:[/green] {timeout}s")
    
    if username:
        console.print(f"[green]Username:[/green] {username}")
    if password:
        console.print("[yellow]Password:[/yellow] [redacted]")
    
    try:
        # Initialize scanner
        scanner = NetworkScanner(timeout=timeout, threads=threads)
        
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
        
        # Store results in database
        active_hosts = [r for r in results if r['status'] == 'active']
        if active_hosts:
            console.print(f"\n[blue]Storing {len(active_hosts)} active hosts in database...[/blue]")
            
            for host_result in active_hosts:
                # Prepare host data for database
                host_data = {
                    'ip_address': host_result['ip_address'],
                    'hostname': host_result.get('hostname'),
                    'ssh_port': host_result['ssh_port'],
                    'status': 'active'
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
@click.option('--username', '-u', required=True, help='SSH username')
@click.option('--password', '-p', help='SSH password')
@click.option('--key-file', '-k', help='SSH private key file path')
@click.option('--port', '-P', default=22, help='SSH port (default: 22)')
@click.option('--timeout', '-T', default=10, help='Connection timeout in seconds (default: 10)')
@click.option('--threads', '-t', default=5, help='Number of concurrent threads (default: 5)')
@click.option('--try-all-methods', is_flag=True, help='Try all available authentication methods')
@click.pass_context
def auth(ctx, hosts, from_db, username, password, key_file, port, timeout, threads, try_all_methods):
    """Test SSH authentication to discovered hosts"""
    
    console.print(Panel.fit(
        Text("NetScan - SSH Authentication Test", style="bold green"),
        border_style="green"
    ))
    
    # Validate inputs
    if not validate_username(username):
        console.print(f"[red]Error: Invalid username format: {username}[/red]")
        sys.exit(1)
    
    if not validate_port(port):
        console.print(f"[red]Error: Invalid port number: {port}[/red]")
        sys.exit(1)
    
    if not validate_timeout(timeout):
        console.print(f"[red]Error: Invalid timeout: {timeout}[/red]")
        sys.exit(1)
    
    if not validate_threads(threads):
        console.print(f"[red]Error: Invalid thread count: {threads}[/red]")
        sys.exit(1)
    
    # Get host list
    host_list = []
    
    if from_db:
        console.print("[blue]Loading hosts from database...[/blue]")
        try:
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
    
    # Check authentication parameters
    if not password and not key_file and not try_all_methods:
        console.print("[red]Error: Must provide --password, --key-file, or --try-all-methods[/red]")
        sys.exit(1)
    
    console.print(f"[green]Username:[/green] {username}")
    console.print(f"[green]SSH port:[/green] {port}")
    console.print(f"[green]Timeout:[/green] {timeout}s")
    console.print(f"[green]Threads:[/green] {threads}")
    
    if password:
        console.print("[yellow]Password:[/yellow] [redacted]")
    if key_file:
        console.print(f"[yellow]Key file:[/yellow] {key_file}")
    if try_all_methods:
        console.print("[yellow]Will try all available authentication methods[/yellow]")
    
    try:
        # Initialize SSH connector
        ssh_connector = SSHConnector(timeout=timeout)
        
        results = []
        
        if try_all_methods:
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
                auth_method = result.get('auth_method', 'unknown')
                console.print(f"[green]✓ {result['host']}:{result['port']} - {auth_method}[/green]")
            else:
                failed_hosts.append(result)
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
@click.option('--username', '-u', required=True, help='SSH username')
@click.option('--password', '-p', help='SSH password')
@click.option('--key-file', '-k', help='SSH private key file path')
@click.option('--port', '-P', default=22, help='SSH port (default: 22)')
@click.option('--timeout', '-T', default=15, help='Connection timeout in seconds (default: 15)')
@click.option('--store-db', is_flag=True, help='Store collected information in database')
@click.option('--output', '-o', help='Output file for detailed results')
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.pass_context
def info(ctx, hosts, from_db, username, password, key_file, port, timeout, store_db, output, format):
    """Collect system information from SSH-accessible hosts"""
    
    console.print(Panel.fit(
        Text("NetScan - System Information Collector", style="bold magenta"),
        border_style="magenta"
    ))
    
    # Validate inputs
    if not validate_username(username):
        console.print(f"[red]Error: Invalid username format: {username}[/red]")
        sys.exit(1)
    
    if not validate_port(port):
        console.print(f"[red]Error: Invalid port number: {port}[/red]")
        sys.exit(1)
    
    if not validate_timeout(timeout):
        console.print(f"[red]Error: Invalid timeout: {timeout}[/red]")
        sys.exit(1)
    
    # Get host list
    host_list = []
    
    if from_db:
        console.print("[blue]Loading hosts from database...[/blue]")
        try:
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
    
    # Check authentication parameters
    if not password and not key_file:
        console.print("[red]Error: Must provide either --password or --key-file[/red]")
        sys.exit(1)
    
    console.print(f"[green]Username:[/green] {username}")
    console.print(f"[green]SSH port:[/green] {port}")
    console.print(f"[green]Timeout:[/green] {timeout}s")
    console.print(f"[green]Output format:[/green] {format}")
    
    if password:
        console.print("[yellow]Password:[/yellow] [redacted]")
    if key_file:
        console.print(f"[yellow]Key file:[/yellow] {key_file}")
    if store_db:
        console.print("[yellow]Will store results in database[/yellow]")
    
    try:
        # Initialize SSH connector and system info collector
        ssh_connector = SSHConnector(timeout=timeout)
        info_collector = SystemInfoCollector(ssh_connector)
        
        # Collect system information
        console.print(f"\n[cyan]Collecting system information from {len(host_list)} hosts...[/cyan]")
        results = info_collector.collect_from_multiple_hosts(
            host_list, port, username, password, key_file
        )
        
        # Display results
        console.print(f"\n[bold blue]System Information Collection Results:[/bold blue]")
        
        successful_collections = []
        failed_collections = []
        
        for result in results:
            if result['collection_success']:
                successful_collections.append(result)
                console.print(f"[green]✓ {result['host']} - Complete system info collected[/green]")
            else:
                failed_collections.append(result)
                error_count = len(result['collection_errors'])
                console.print(f"[red]✗ {result['host']} - {error_count} collection errors[/red]")
        
        # Summary
        console.print(f"\n[bold blue]Collection Summary:[/bold blue]")
        console.print(f"[green]Successful collections:[/green] {len(successful_collections)}")
        console.print(f"[red]Failed collections:[/red] {len(failed_collections)}")
        success_rate = (len(successful_collections) / len(results)) * 100 if results else 0
        console.print(f"[cyan]Success rate:[/cyan] {success_rate:.1f}%")
        
        # Store in database if requested
        if store_db and successful_collections:
            console.print(f"\n[blue]Storing system information in database...[/blue]")
            
            for result in successful_collections:
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
                    
                    # Create or update host in database
                    db_manager.create_host(host_data)
                    
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
        if successful_collections:
            console.print(f"\n[bold blue]Sample System Information:[/bold blue]")
            sample = successful_collections[0]
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
@click.option('--set-username', help='Set default SSH username')
@click.option('--set-password', help='Set default SSH password')
@click.option('--set-port', type=int, help='Set default SSH port')
@click.option('--set-threads', type=int, help='Set default number of threads')
@click.option('--set-timeout', type=int, help='Set default timeout')
@click.option('--set-auth-timeout', type=int, help='Set SSH authentication timeout')
@click.option('--set-preferred-auth', type=click.Choice(['key', 'password', 'agent']), help='Set preferred authentication method')
@click.option('--set-log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']), help='Set logging level')
@click.pass_context
def set(ctx, set_username, set_password, set_port, set_threads, set_timeout, set_auth_timeout, set_preferred_auth, set_log_level):
    """Set configuration values"""
    
    console.print(Panel.fit(
        Text("NetScan - Configuration", style="bold blue"),
        border_style="blue"
    ))
    
    from .config import config_manager
    
    try:
        changes_made = False
        
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