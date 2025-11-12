"""
Output formatting module for NetScan reports

This module handles formatting report data for different output formats.
"""

import json
import csv
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from datetime import datetime
import io

from ..database.models import Host, ScanHistory

console = Console()


class ReportFormatter:
    """Report formatter class for various output formats"""
    
    def __init__(self):
        self.supported_formats = ['table', 'json', 'csv', 'text']
    
    def format_hosts_table(self, hosts: List[Host], title: str = "Discovered Hosts") -> Table:
        """Format hosts data as a Rich table"""
        
        table = Table(title=title, show_header=True, header_style="bold magenta")
        
        # Add columns
        table.add_column("IP Address", style="cyan", no_wrap=True)
        table.add_column("Hostname", style="green")
        table.add_column("SSH Port", justify="right", style="yellow")
        table.add_column("Extra Ports", style="yellow")
        table.add_column("Status", style="bold")
        table.add_column("OS Info", style="blue")
        table.add_column("CPU Info", style="yellow")
        table.add_column("Uptime", style="magenta")
        table.add_column("Memory", justify="right", style="cyan")
        table.add_column("Last Scan", style="dim")
        
        # Add rows
        for host in hosts:
            # Status styling
            if host.status == 'active':
                status = "[green]Active[/green]"
            elif host.status == 'inactive':
                status = "[red]Inactive[/red]"
            else:
                status = "[yellow]Error[/yellow]"
            
            # Memory formatting
            memory_str = "N/A"
            if host.memory_total and host.memory_used:
                usage_pct = (host.memory_used / host.memory_total) * 100
                memory_str = f"{host.memory_used}MB/{host.memory_total}MB ({usage_pct:.1f}%)"
            
            # Last scan formatting
            last_scan_str = "Never"
            if host.last_scan:
                last_scan_str = host.last_scan.strftime("%Y-%m-%d %H:%M")
            
            # CPU info formatting
            cpu_str = "Unknown"
            if host.cpu_info:
                # Truncate long CPU model names for display
                cpu_str = host.cpu_info[:30] + "..." if len(host.cpu_info) > 30 else host.cpu_info
            
            extra_ports_display = self._format_open_ports(host)
            
            table.add_row(
                host.ip_address,
                host.hostname or "Unknown",
                str(host.ssh_port),
                extra_ports_display,
                status,
                host.os_info or "Unknown",
                cpu_str,
                host.uptime or "Unknown",
                memory_str,
                last_scan_str
            )
        
        return table
    
    def format_hosts_json(self, hosts: List[Host]) -> str:
        """Format hosts data as JSON"""
        hosts_data = []
        
        for host in hosts:
            host_dict = host.to_dict()
            hosts_data.append(host_dict)
        
        return json.dumps(hosts_data, indent=2, default=str)
    
    def format_hosts_csv(self, hosts: List[Host]) -> str:
        """Format hosts data as CSV"""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'IP Address', 'Hostname', 'SSH Port', 'Status', 'OS Info',
            'Kernel Version', 'Uptime', 'CPU Info', 'Memory Total (MB)',
            'Memory Used (MB)', 'Disk Usage', 'Open Ports', 'Last Scan', 'Created At'
        ])
        
        # Write data
        for host in hosts:
            extra_ports_display = self._format_open_ports(host, plain_text=True)
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
                host.disk_usage or '',
                extra_ports_display,
                host.last_scan.isoformat() if host.last_scan else '',
                host.created_at.isoformat() if host.created_at else ''
            ])
        
        return output.getvalue()
    
    def format_hosts_text(self, hosts: List[Host]) -> str:
        """Format hosts data as plain text"""
        output = []
        output.append("NetScan Host Report")
        output.append("=" * 50)
        output.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output.append(f"Total hosts: {len(hosts)}")
        output.append("")
        
        for i, host in enumerate(hosts, 1):
            output.append(f"Host #{i}: {host.ip_address}")
            output.append("-" * 30)
            output.append(f"  Hostname: {host.hostname or 'Unknown'}")
            output.append(f"  SSH Port: {host.ssh_port}")
            output.append(f"  Status: {host.status}")
            output.append(f"  OS Info: {host.os_info or 'Unknown'}")
            output.append(f"  Kernel: {host.kernel_version or 'Unknown'}")
            output.append(f"  Uptime: {host.uptime or 'Unknown'}")
            output.append(f"  CPU: {host.cpu_info or 'Unknown'}")
            
            extra_ports_display = self._format_open_ports(host, plain_text=True)
            output.append(f"  Extra Ports: {extra_ports_display or 'None'}")
            
            if host.memory_total and host.memory_used:
                usage_pct = (host.memory_used / host.memory_total) * 100
                output.append(f"  Memory: {host.memory_used}MB/{host.memory_total}MB ({usage_pct:.1f}%)")
            else:
                output.append(f"  Memory: Unknown")
            
            output.append(f"  Last Scan: {host.last_scan.strftime('%Y-%m-%d %H:%M:%S') if host.last_scan else 'Never'}")
            output.append("")
        
        return "\n".join(output)
    
    @staticmethod
    def _parse_host_open_ports(host: Host) -> List[Dict[str, Any]]:
        raw_value = getattr(host, 'open_ports', None)
        if not raw_value:
            return []
        if isinstance(raw_value, str):
            try:
                data = json.loads(raw_value)
            except (ValueError, TypeError):
                return []
        elif isinstance(raw_value, list):
            data = raw_value
        else:
            return []
        
        normalized = []
        for entry in data:
            if isinstance(entry, dict):
                port = entry.get('port')
                service = entry.get('service')
            elif isinstance(entry, (list, tuple)) and entry:
                port = entry[0]
                service = entry[1] if len(entry) > 1 else None
            else:
                try:
                    port = int(entry)
                    service = None
                except (TypeError, ValueError):
                    continue
            if port is None:
                continue
            try:
                port_int = int(port)
            except (TypeError, ValueError):
                continue
            normalized.append({
                'port': port_int,
                'service': service
            })
        return normalized
    
    def _format_open_ports(self, host: Host, plain_text: bool = False) -> str:
        ports = self._parse_host_open_ports(host)
        if not ports:
            return "" if plain_text else "—"
        pieces = []
        for entry in sorted(ports, key=lambda item: item['port']):
            label = str(entry['port'])
            service = entry.get('service')
            if service:
                label = f"{label} ({service})"
            pieces.append(label)
        separator = ", "
        return separator.join(pieces)
    
    def format_scan_history_table(self, scan_history: List[ScanHistory], title: str = "Scan History") -> Table:
        """Format scan history as a Rich table"""
        
        table = Table(title=title, show_header=True, header_style="bold cyan")
        
        # Add columns
        table.add_column("ID", justify="right", style="dim")
        table.add_column("Host ID", justify="right", style="cyan")
        table.add_column("Scan Type", style="green")
        table.add_column("Result", style="blue")
        table.add_column("Duration", justify="right", style="yellow")
        table.add_column("Timestamp", style="magenta")
        table.add_column("Error", style="red")
        
        # Add rows
        for scan in scan_history:
            error_str = scan.error_message or ""
            if len(error_str) > 50:
                error_str = error_str[:47] + "..."
            
            duration_str = f"{scan.scan_duration:.2f}s" if scan.scan_duration else "N/A"
            
            table.add_row(
                str(scan.id),
                str(scan.host_id),
                scan.scan_type or "Unknown",
                scan.result or "N/A",
                duration_str,
                scan.timestamp.strftime("%Y-%m-%d %H:%M:%S") if scan.timestamp else "Unknown",
                error_str
            )
        
        return table
    
    def format_statistics_panel(self, stats: Dict[str, Any]) -> Panel:
        """Format statistics as a Rich panel"""
        
        content = []
        content.append(f"[bold green]Total Hosts:[/bold green] {stats.get('total_hosts', 0)}")
        content.append(f"[bold green]Active Hosts:[/bold green] {stats.get('active_hosts', 0)}")
        content.append(f"[bold yellow]Inactive Hosts:[/bold yellow] {stats.get('inactive_hosts', 0)}")
        content.append(f"[bold red]Error Hosts:[/bold red] {stats.get('error_hosts', 0)}")
        
        if stats.get('total_hosts', 0) > 0:
            success_rate = (stats.get('active_hosts', 0) / stats.get('total_hosts', 1)) * 100
            content.append(f"[bold cyan]Success Rate:[/bold cyan] {success_rate:.1f}%")
        
        return Panel(
            "\n".join(content),
            title="[bold blue]Host Statistics[/bold blue]",
            border_style="blue"
        )
    
    def format_summary(self, hosts: Optional[List[Host]] = None, stats: Optional[Dict[str, Any]] = None) -> str:
        """Format summary report - alias for create_summary_report"""
        # If no hosts provided, get them from database
        if hosts is None:
            from ..database.operations import db_manager
            hosts = db_manager.get_all_hosts()
        
        # If no stats provided, calculate them
        if stats is None:
            stats = {
                'total_hosts': len(hosts),
                'active_hosts': len([h for h in hosts if h.status == 'active']),
                'inactive_hosts': len([h for h in hosts if h.status == 'inactive']),
                'error_hosts': len([h for h in hosts if h.status == 'error']),
            }
        
        return self.create_summary_report(hosts, stats)
    
    def create_summary_report(self, hosts: List[Host], stats: Dict[str, Any]) -> str:
        """Create a comprehensive summary report"""
        
        output = []
        output.append("NetScan Summary Report")
        output.append("=" * 60)
        output.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output.append("")
        
        # Statistics
        output.append("STATISTICS")
        output.append("-" * 20)
        output.append(f"Total Hosts: {stats.get('total_hosts', 0)}")
        output.append(f"Active Hosts: {stats.get('active_hosts', 0)}")
        output.append(f"Inactive Hosts: {stats.get('inactive_hosts', 0)}")
        output.append(f"Error Hosts: {stats.get('error_hosts', 0)}")
        
        if stats.get('total_hosts', 0) > 0:
            success_rate = (stats.get('active_hosts', 0) / stats.get('total_hosts', 1)) * 100
            output.append(f"Success Rate: {success_rate:.1f}%")
        output.append("")
        
        # OS Distribution
        os_distribution = {}
        for host in hosts:
            if host.os_info:
                # Extract OS name from os_info
                os_name = host.os_info.split()[0] if host.os_info else "Unknown"
                os_distribution[os_name] = os_distribution.get(os_name, 0) + 1
        
        if os_distribution:
            output.append("OS DISTRIBUTION")
            output.append("-" * 20)
            for os_name, count in sorted(os_distribution.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / len(hosts)) * 100
                output.append(f"{os_name}: {count} ({percentage:.1f}%)")
            output.append("")
        
        # Memory Usage Summary
        total_memory = sum(host.memory_total for host in hosts if host.memory_total)
        used_memory = sum(host.memory_used for host in hosts if host.memory_used)
        hosts_with_memory = len([host for host in hosts if host.memory_total])
        
        if hosts_with_memory > 0:
            output.append("MEMORY USAGE SUMMARY")
            output.append("-" * 20)
            output.append(f"Hosts with memory data: {hosts_with_memory}")
            output.append(f"Total memory across all hosts: {total_memory:,} MB")
            output.append(f"Used memory across all hosts: {used_memory:,} MB")
            if total_memory > 0:
                avg_usage = (used_memory / total_memory) * 100
                output.append(f"Average memory usage: {avg_usage:.1f}%")
            output.append("")
        
        # Recent Activity
        recent_hosts = sorted([host for host in hosts if host.last_scan], 
                            key=lambda x: x.last_scan, reverse=True)[:10]
        
        if recent_hosts:
            output.append("RECENT ACTIVITY (Last 10 scanned hosts)")
            output.append("-" * 40)
            for host in recent_hosts:
                scan_time = host.last_scan.strftime('%Y-%m-%d %H:%M:%S')
                output.append(f"{scan_time} - {host.ip_address} ({host.hostname or 'Unknown'})")
            output.append("")
        
        return "\n".join(output) 