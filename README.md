# NetScan - SSH Network Scanner

A powerful Python CLI tool for discovering and analyzing Linux servers with SSH capability. NetScan allows you to scan networks, collect system information, and generate comprehensive reports with enterprise-grade features.

## Features

- 🔍 **Network Discovery**: Scan IP ranges for SSH-enabled hosts with optimized timeouts
- 🔐 **Multiple Credentials**: Support for testing multiple username/password combinations
- 📊 **System Information**: Collect OS, CPU, memory, and disk usage data
- ⚡ **Comprehensive Scanning**: Complete workflow in one command (`scan full`)
- 💾 **Data Persistence**: SQLite database for storing scan results and authentication details
- 📋 **Rich Reports**: Beautiful CLI output with filtering and export options
- 🔧 **Configuration Management**: Persistent settings and secure credential storage
- 🎯 **Optimized Performance**: Fast connection testing with configurable timeouts
- 🔦 **Additional Port Discovery**: Probe configurable TCP ports alongside SSH for richer host context

## Installation

### From Source

```bash
git clone https://github.com/yourusername/netscan.git
cd netscan
pip install -e .
```

### Dependencies

- Python 3.8+
- nmap (optional, for faster network discovery)

Install nmap on your system:

```bash
# Ubuntu/Debian
sudo apt-get install nmap

# CentOS/RHEL
sudo yum install nmap

# macOS
brew install nmap
```

## Quick Start

### Complete Network Analysis (Recommended)

```bash
# Create a credentials file with multiple username/password pairs
cat > credentials.txt <<'EOF'
admin:admin
admin:password
root:root
root:password
ubuntu:ubuntu
EOF

# Run the entire workflow (discovery → auth → info → storage) in one command
python -m netscan scan full --range 192.168.1.0/24 --credentials-file credentials.txt
```

### Classic Step-by-Step Workflow

1. **Store credentials (optional).** When values are omitted NetScan prompts securely and persists them:

   ```bash
   python -m netscan config set-credential username ubuntu
   python -m netscan config set-credential password
   ```

2. **Discover SSH endpoints.** Reuse stored credentials or supply them inline; tune timeouts/retries as needed:

   ```bash
   python -m netscan scan network --range 192.168.1.0/24 --timeout 2 --threads 25 --retries 0
   ```

3. **Authenticate against hosts.** Try single or multiple credentials and persist working pairs to the database:

   ```bash
   python -m netscan scan auth --from-db --multiple-usernames admin,root,user \
       --multiple-passwords admin,password,123456 --try-multiple-credentials
   ```

4. **Collect system information** (CPU, memory, disk, uptime) and store the results:

   ```bash
   python -m netscan scan info --from-db --credentials-file credentials.txt \
       --try-multiple-credentials --store-db
   ```

5. **Review or export the data:**

   ```bash
   python -m netscan report hosts --format table
   python -m netscan report summary
   python -m netscan report export --format json --output results.json
   ```

### Configuration Management Highlights

- Dot-notation mirrors the config structure and keeps legacy aliases working:

  ```bash
  python -m netscan config set scanning.default_timeout 2
  python -m netscan config set scanning.max_retries 1
  ```

- Credential helpers remain available:

  ```bash
  python -m netscan config set-credential ssh_key_path /home/user/.ssh/id_rsa
  python -m netscan config list-credentials
  python -m netscan config show
  ```

- Additional port scanning is easily configured:

  ```bash
  python -m netscan config set --set-additional-ports 80,443,3389
  python -m netscan config set scanning.additional_ports 5900
  ```

### Reporting Shortcuts

```bash
# Filter hosts by OS substring and show the newest first
python -m netscan report hosts --filter "os=ubuntu" --sort last_scan

# Export hosts as CSV and include scan history in JSON
python -m netscan report export --format csv --output hosts.csv
python -m netscan report export --include-history --output hosts.json
```

## Usage

### Command Groups

- `scan full` – **Complete workflow** (Discovery → Authentication → Info Collection) ⭐
- `scan network` – Discover SSH-enabled hosts and populate the inventory
- `scan auth` – Test SSH authentication (single or multiple credentials)
- `scan info` – Collect detailed system information
- `report` – Generate and export reports
- `config` – Manage configuration settings and stored credentials
- `database` – Maintenance utilities (backup, vacuum, restore)

| Command | Description |
|---------|-------------|
| `python -m netscan scan network` | Discover SSH endpoints, auto-updating the host inventory. |
| `python -m netscan scan auth` | Test authentication (password/key/agent or credential lists) against known hosts. |
| `python -m netscan scan info` | Collect OS/CPU/memory/disk details; partial successes still update the DB. |
| `python -m netscan report hosts` | Render hosts in table/json/csv/text with filter, sort, limit controls. |
| `python -m netscan report summary` | Show aggregated host stats, OS distribution, recent activity. |
| `python -m netscan report export` | Export hosts (and optionally history) to json/csv/xml/txt/sql. |
| `python -m netscan config ...` | Manage configuration and credentials (supports aliases and dot keys). |
| `python -m netscan database ...` | Maintenance utilities (backup, vacuum, restore). |

### Key Scan Options

- `--range / -r`: IP range to scan (CIDR or single IP, required for `scan network`).
- `--username / -u`: SSH username (optional for network discovery; required for single-credential auth/info).
- `--multiple-usernames`: Comma-separated usernames to iterate through.
- `--password / -p`: SSH password; omit value to prompt securely and fall back to stored secrets if available.
- `--multiple-passwords`: Comma-separated passwords matching `--multiple-usernames`.
- `--credentials-file`: Path to username:password pairs (one per line).
- `--key-file / -k`: Path to SSH private key.
- `--port / -P`: SSH port (default 22).
- `--threads / -t`: Concurrent workers (1–100, defaults to config `scanning.default_threads`).
- `--timeout / -T`: Socket/SSH timeout in seconds (1–300).
- `--retries / -R`: Number of retries for unreachable hosts during network scans (0–10, default from config).
- `--try-multiple-credentials`: Enable the multi-credential authentication/collection workflow.
- `--no-nmap`: Skip the nmap pre-scan and force socket-only discovery.
- `--store-db`: Persist info-collection results (complete and partial datasets) to the database.

### Report Options Snapshot

- `--filter`: `key=value` filter (`status`, `os`, `ip`, `hostname`, `port` for hosts; similar patterns elsewhere).
- `--format / --Format`: Switch output between table/json/csv/text.
- `--output`: Write report/export to file.
- `--sort`: Sort column (e.g., `last_scan`, `ip_address`).
- `--limit`: Cap the number of rows displayed.

## Database Schema

NetScan uses SQLite to store scan results with the following structure:

- **hosts**: Host information, system details, and authentication data
- **scan_history**: Historical scan records
- **config**: Application configuration

## Development

See [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) for detailed architecture and development information.

### Running Tests

```bash
./venv/bin/pytest
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Security Considerations

- Store credentials securely (consider using SSH keys)
- Use strong authentication methods
- Implement proper access controls
- Regular security audits

## License

MIT License - see LICENSE file for details.

## Support

For issues and feature requests, please use the GitHub issue tracker. 