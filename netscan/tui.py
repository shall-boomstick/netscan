from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, Tabs, Tab, TabbedContent, TabPane, Input, Checkbox, Button, LoadingIndicator, ProgressBar
from textual.containers import Container, Vertical
from textual.reactive import reactive
from textual.message import Message
import threading

# Import scan logic
from netscan.scanner.comprehensive import ComprehensiveScanner
from netscan.database.operations import db_manager
from netscan.reporting.formatter import ReportFormatter
from netscan.reporting.exporter import ReportExporter
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class MainMenu(Static):
    def compose(self) -> ComposeResult:
        yield Tabs(
            Tab("Scan", id="scan"),
            Tab("Report", id="report"),
            Tab("Config", id="config"),
            Tab("Database", id="database"),
            Tab("Exit", id="exit"),
            id="main-tabs",
        )

class SectionPanel(Static):
    def __init__(self, title: str, content: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title = title
        self.content = content

    def compose(self) -> ComposeResult:
        yield Static(f"[b]{self.title}[/b]", classes="section-title")
        yield Static(self.content, classes="section-content")

class ScanForm(Static):
    class ScanComplete(Message):
        def __init__(self, results, summary):
            self.results = results
            self.summary = summary
            super().__init__()

    class ScanError(Message):
        def __init__(self, error):
            self.error = error
            super().__init__()

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("[b]Full Scan Workflow[/b]", classes="form-title")
            yield Input(placeholder="IP Range (e.g. 192.168.1.0/24)", id="ip_range")
            yield Input(placeholder="SSH Port (default 22)", id="port")
            yield Input(placeholder="Username(s) (comma-separated)", id="username")
            yield Input(placeholder="Password(s) (comma-separated)", id="password", password=True)
            yield Input(placeholder="Key file path", id="key_file")
            yield Input(placeholder="Credentials file (username:password per line)", id="credentials_file")
            yield Input(placeholder="Threads (default 10)", id="threads")
            yield Input(placeholder="Timeout (default 5)", id="timeout")
            yield Checkbox("Use nmap", id="use_nmap", value=True)
            yield Checkbox("Store in DB", id="store_db", value=True)
            yield Button("Start Full Scan", id="start_scan", variant="primary")
            yield Static("", id="scan_status")
            yield ProgressBar(total=100, id="scan_progress")
            yield Static("", id="scan_results")
            yield LoadingIndicator(id="scan_spinner", classes="scan-spinner")

    def update_progress(self, percent: float, message: str = ""):
        bar = self.query_one("#scan_progress", ProgressBar)
        bar.progress = int(percent * 100)
        if message:
            self.query_one("#scan_status", Static).update(message)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start_scan":
            self.run_scan()

    def run_scan(self):
        # Collect form values
        ip_range = self.query_one("#ip_range", Input).value.strip()
        port = self.query_one("#port", Input).value.strip() or "22"
        username = self.query_one("#username", Input).value.strip()
        password = self.query_one("#password", Input).value.strip()
        key_file = self.query_one("#key_file", Input).value.strip()
        credentials_file = self.query_one("#credentials_file", Input).value.strip()
        threads = self.query_one("#threads", Input).value.strip() or "10"
        timeout = self.query_one("#timeout", Input).value.strip() or "5"
        use_nmap = self.query_one("#use_nmap", Checkbox).value
        store_db = self.query_one("#store_db", Checkbox).value

        # Use credentials.txt as default if not provided and file exists
        import os
        if not credentials_file and os.path.exists("credentials.txt"):
            credentials_file = "credentials.txt"

        # Validate required fields
        if not ip_range:
            self.query_one("#scan_status", Static).update("[red]IP range is required.[/red]")
            return
        if not (username or credentials_file):
            self.query_one("#scan_status", Static).update("[red]Username or credentials file is required (or credentials.txt must exist).[/red]")
            return

        # Parse credentials
        credentials_list = []
        if credentials_file:
            try:
                with open(credentials_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if ':' in line:
                                cred_username, cred_password = line.split(':', 1)
                                credentials_list.append({
                                    'username': cred_username.strip(),
                                    'password': cred_password.strip()
                                })
            except Exception as e:
                self.query_one("#scan_status", Static).update(f"[red]Error reading credentials file: {e}[/red]")
                return
        elif username:
            usernames = [u.strip() for u in username.split(',') if u.strip()]
            passwords = [p.strip() for p in password.split(',') if p.strip()]
            if len(usernames) > 1 and len(passwords) == len(usernames):
                for u, p in zip(usernames, passwords):
                    credentials_list.append({'username': u, 'password': p})
            else:
                for u in usernames:
                    cred = {'username': u}
                    if password:
                        cred['password'] = password
                    if key_file:
                        cred['key_file'] = key_file
                    credentials_list.append(cred)

        # Convert types
        try:
            port = int(port)
            threads = int(threads)
            timeout = int(timeout)
        except Exception as e:
            self.query_one("#scan_status", Static).update(f"[red]Port, threads, and timeout must be integers.[/red]")
            return

        # Show spinner, show status/results
        self.query_one("#scan_status", Static).update("[yellow]Scanning...[/yellow]")
        self.query_one("#scan_results", Static).update("")
        self.query_one("#scan_spinner", LoadingIndicator).visible = True
        self.query_one("#scan_progress", ProgressBar).progress = 0

        # Run scan in background thread, pass progress callback
        threading.Thread(
            target=self._run_scan_thread,
            args=(ip_range, port, credentials_list, store_db, use_nmap, timeout, threads),
            daemon=True
        ).start()

    def _run_scan_thread(self, ip_range, port, credentials_list, store_db, use_nmap, timeout, threads):
        def progress_callback(percent, message):
            # Safely update UI from background thread
            self.app.call_from_thread(self.update_progress, percent, message)
        try:
            scanner = ComprehensiveScanner(timeout=timeout, threads=threads)
            results = scanner.comprehensive_scan(
                ip_range=ip_range,
                port=port,
                credentials=credentials_list,
                store_db=store_db,
                use_nmap=use_nmap,
                progress_callback=progress_callback
            )
            summary = self._format_summary(results)
            self.post_message(self.ScanComplete(results, summary))
        except Exception as e:
            self.post_message(self.ScanError(str(e)))

    def _format_summary(self, results):
        # Build a summary string from results dict
        lines = []
        lines.append(f"[b]Scan Summary[/b]")
        net = results['network_discovery']
        lines.append(f"[cyan]SSH hosts found:[/cyan] {net['ssh_hosts_found']}")
        auth = results['authentication']
        lines.append(f"[green]Hosts authenticated:[/green] {auth['successful_auths']} / {auth['hosts_tested']}")
        info = results['system_info']
        lines.append(f"[magenta]Info collected:[/magenta] {info['successful_collections']} / {info['hosts_collected']}")
        db = results['database_storage']
        lines.append(f"[yellow]Hosts stored in DB:[/yellow] {db['hosts_stored']}")
        lines.append(f"[dim]Total duration: {results.get('scan_end_time', 0) - results.get('scan_start_time', 0):.1f}s[/dim]")
        return '\n'.join(lines)

    def on_scan_complete(self, message: ScanComplete) -> None:
        self.query_one("#scan_spinner", LoadingIndicator).visible = False
        self.query_one("#scan_status", Static).update("[green]Scan complete![/green]")
        self.query_one("#scan_results", Static).update(message.summary)
        self.query_one("#scan_progress", ProgressBar).progress = 100

    def on_scan_error(self, message: ScanError) -> None:
        self.query_one("#scan_spinner", LoadingIndicator).visible = False
        self.query_one("#scan_status", Static).update(f"[red]Scan error: {message.error}[/red]")
        self.query_one("#scan_results", Static).update("")
        self.query_one("#scan_progress", ProgressBar).progress = 0

class ReportForm(Static):
    """Report generation form"""
    
    class ReportComplete(Message):
        def __init__(self, report_data, report_type):
            self.report_data = report_data
            self.report_type = report_type
            super().__init__()
    
    class ReportError(Message):
        def __init__(self, error):
            self.error = error
            super().__init__()
    
    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("[b]Report Generation[/b]", classes="form-title")
            yield Input(placeholder="Filter (e.g., os=ubuntu, status=active)", id="filter")
            yield Input(placeholder="Sort by (e.g., ip_address, hostname, last_scan)", id="sort")
            yield Input(placeholder="Limit results", id="limit")
            yield Input(placeholder="Output file (optional)", id="output_file")
            yield Static("Report Type:", classes="form-label")
            yield Checkbox("Hosts Table", id="report_hosts", value=True)
            yield Checkbox("Statistics", id="report_stats", value=False)
            yield Checkbox("Scan History", id="report_history", value=False)
            yield Static("Export Format:", classes="form-label")
            yield Checkbox("JSON", id="export_json", value=False)
            yield Checkbox("CSV", id="export_csv", value=False)
            yield Checkbox("Text", id="export_text", value=False)
            yield Button("Generate Report", id="generate_report", variant="primary")
            yield Static("", id="report_status")
            yield Static("", id="report_results")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "generate_report":
            self.generate_report()
    
    def generate_report(self):
        """Generate report based on form selections"""
        try:
            # Get form values
            filter_text = self.query_one("#filter", Input).value
            sort_text = self.query_one("#sort", Input).value
            limit_text = self.query_one("#limit", Input).value
            output_file = self.query_one("#output_file", Input).value
            
            # Get report type selections
            report_hosts = self.query_one("#report_hosts", Checkbox).value
            report_stats = self.query_one("#report_stats", Checkbox).value
            report_history = self.query_one("#report_history", Checkbox).value
            
            # Get export format selections
            export_json = self.query_one("#export_json", Checkbox).value
            export_csv = self.query_one("#export_csv", Checkbox).value
            export_text = self.query_one("#export_text", Checkbox).value
            
            # Update status
            self.query_one("#report_status", Static).update("[yellow]Generating report...[/yellow]")
            self.query_one("#report_results", Static).update("")
            
            # Run report generation in background thread
            threading.Thread(
                target=self._generate_report_thread,
                args=(filter_text, sort_text, limit_text, output_file, 
                      report_hosts, report_stats, report_history,
                      export_json, export_csv, export_text),
                daemon=True
            ).start()
            
        except Exception as e:
            self.query_one("#report_status", Static).update(f"[red]Error: {str(e)}[/red]")
    
    def _generate_report_thread(self, filter_text, sort_text, limit_text, output_file,
                               report_hosts, report_stats, report_history,
                               export_json, export_csv, export_text):
        """Generate report in background thread"""
        try:
            formatter = ReportFormatter()
            exporter = ReportExporter()
            report_data = {}
            
            # Get hosts from database
            hosts = db_manager.get_all_hosts()
            
            if not hosts:
                self.post_message(self.ReportError("No hosts found in database. Run a scan first."))
                return
            
            # Apply filters
            if filter_text:
                # Simple filter implementation
                filtered_hosts = []
                for host in hosts:
                    if "os=" in filter_text.lower():
                        os_name = filter_text.split("=")[1].strip()
                        if host.os_info and os_name.lower() in host.os_info.lower():
                            filtered_hosts.append(host)
                    elif "status=" in filter_text.lower():
                        status = filter_text.split("=")[1].strip()
                        if host.status == status:
                            filtered_hosts.append(host)
                    else:
                        # General search
                        search_term = filter_text.lower()
                        if (search_term in host.ip_address.lower() or
                            (host.hostname and search_term in host.hostname.lower()) or
                            (host.os_info and search_term in host.os_info.lower())):
                            filtered_hosts.append(host)
                hosts = filtered_hosts
            
            # Apply sorting
            if sort_text:
                reverse = False
                if sort_text.startswith("-"):
                    reverse = True
                    sort_text = sort_text[1:]
                
                if hasattr(hosts[0], sort_text):
                    hosts = sorted(hosts, key=lambda x: getattr(x, sort_text), reverse=reverse)
            
            # Apply limit
            if limit_text:
                try:
                    limit = int(limit_text)
                    hosts = hosts[:limit]
                except ValueError:
                    pass
            
            # Generate reports
            if report_hosts:
                table = formatter.format_hosts_table(hosts)
                report_data['hosts_table'] = table
            
            if report_stats:
                stats = {
                    'total_hosts': len(hosts),
                    'active_hosts': len([h for h in hosts if h.status == 'active']),
                    'inactive_hosts': len([h for h in hosts if h.status == 'inactive']),
                    'error_hosts': len([h for h in hosts if h.status == 'error']),
                }
                stats_panel = formatter.format_statistics_panel(stats)
                report_data['statistics'] = stats_panel
            
            if report_history:
                history = db_manager.get_scan_history(limit=50)
                if history:
                    history_table = formatter.format_scan_history_table(history)
                    report_data['scan_history'] = history_table
            
            # Export if requested
            export_results = []
            if export_json and hosts:
                json_data = exporter.export_hosts_json(hosts)
                if output_file:
                    json_file = f"{output_file}.json"
                    with open(json_file, 'w') as f:
                        f.write(json_data)
                    export_results.append(f"JSON exported to {json_file}")
                else:
                    export_results.append("JSON data generated")
            
            if export_csv and hosts:
                csv_data = exporter.export_hosts_csv(hosts)
                if output_file:
                    csv_file = f"{output_file}.csv"
                    with open(csv_file, 'w') as f:
                        f.write(csv_data)
                    export_results.append(f"CSV exported to {csv_file}")
                else:
                    export_results.append("CSV data generated")
            
            if export_text and hosts:
                text_data = formatter.format_hosts_text(hosts)
                if output_file:
                    text_file = f"{output_file}.txt"
                    with open(text_file, 'w') as f:
                        f.write(text_data)
                    export_results.append(f"Text exported to {text_file}")
                else:
                    export_results.append("Text data generated")
            
            self.post_message(self.ReportComplete(report_data, export_results))
            
        except Exception as e:
            self.post_message(self.ReportError(str(e)))
    
    def on_report_complete(self, message: ReportComplete) -> None:
        """Handle report completion"""
        self.query_one("#report_status", Static).update("[green]Report generated successfully![/green]")
        
        # Display results
        results = []
        results.append(f"[bold]Report Results:[/bold]")
        results.append(f"Total hosts processed: {len(message.report_data.get('hosts_table', []).rows) if 'hosts_table' in message.report_data else 0}")
        
        if message.report_type:
            results.append("")
            results.append("[bold]Exports:[/bold]")
            for export in message.report_type:
                results.append(f"✓ {export}")
        
        # Show table or panel if present, else show summary
        results_widget = self.query_one("#report_results", Static)
        if "hosts_table" in message.report_data:
            results_widget.update(message.report_data["hosts_table"])
        elif "statistics" in message.report_data:
            results_widget.update(message.report_data["statistics"])
        elif "scan_history" in message.report_data:
            results_widget.update(message.report_data["scan_history"])
        else:
            results_widget.update("\n".join(results))
    
    def on_report_error(self, message: ReportError) -> None:
        """Handle report error"""
        self.query_one("#report_status", Static).update(f"[red]Report error: {message.error}[/red]")
        self.query_one("#report_results", Static).update("")

class NetScanTUI(App):
    """NetScan Text User Interface"""
    
    CSS_PATH = None
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("ctrl+c", "quit", "Quit"),
    ]
    current_tab = reactive("scan")

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        yield Footer()
        
        with TabbedContent():
            with TabPane("Scan", id="scan-tab"):
                yield ScanForm()
            
            with TabPane("Reports", id="reports-tab"):
                yield ReportForm()
            
            with TabPane("Database", id="database-tab"):
                yield Static("Database management coming soon...", classes="placeholder")
            
            with TabPane("Settings", id="settings-tab"):
                yield Static("Settings coming soon...", classes="placeholder")

    def on_tabs_tab_activated(self, event: Tabs.TabActivated) -> None:
        self.current_tab = event.tab.id
        tabbed_content = self.query_one("#main-content", TabbedContent)
        tabbed_content.active = self.current_tab
        if self.current_tab == "exit":
            self.exit()

if __name__ == "__main__":
    NetScanTUI().run() 