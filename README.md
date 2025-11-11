# NetScan - SSH Network Scanner

A powerful Python CLI tool for discovering and analyzing Linux servers with SSH capability. NetScan allows you to scan networks, collect system information, and generate comprehensive reports.

## Features

- 🔍 **Network Discovery**: Scan IP ranges for SSH-enabled hosts
- 🔐 **SSH Authentication**: Support for password and key-based authentication
- 📊 **System Information**: Collect OS, CPU, memory, and disk usage data
- 💾 **Data Persistence**: SQLite database for storing scan results
- 📋 **Rich Reports**: Beautiful CLI output with filtering and export options
- ⚡ **Concurrent Scanning**: Multi-threaded scanning for performance
- 🔧 **Configuration Management**: Persistent settings and credentials

## Installation

### From Source

```bash
git clone https://github.com/yourusername/netscan.git
cd netscan
pip install -e .
```

### Dependencies

- Python 3.8+
- nmap (system package)

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

### Typical Workflow

1. **Save credentials once** (prompts when value omitted):

   ```bash
   python -m netscan config set-credential username ubuntu
   python -m netscan config set-credential password
   ```

2. **Scan the network** (uses stored credentials automatically, configurable timeouts/retries):

   ```bash
   python -m netscan scan network --range 192.168.1.0/24 --timeout 2 --threads 25 --retries 0
   ```

3. **Collect system info for active hosts** and store the results:

   ```bash
   python -m netscan scan info --from-db --username ubuntu --password --store-db
   ```

4. **Review the data**:

   ```bash
   python -m netscan report hosts --format table
   python -m netscan report summary
   ```

### Configuration Management Highlights

- Dot-notation keys mirror the config structure:

  ```bash
  python -m netscan config set scanning.default_timeout 2
  python -m netscan config set scanning.max_retries 1
  ```

- Credential helpers:

  ```bash
  python -m netscan config set-credential ssh_key_path /home/user/.ssh/id_rsa
  python -m netscan config list-credentials
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

| Command | Description |
|---------|-------------|
| `python -m netscan scan network` | Discover SSH endpoints, auto-updating the host inventory. |
| `python -m netscan scan auth` | Test authentication (password/key/agent) against known hosts. |
| `python -m netscan scan info` | Collect OS/CPU/memory/disk details; partial successes still update the DB. |
| `python -m netscan report hosts` | Render hosts in table/json/csv/text with filter, sort, limit controls. |
| `python -m netscan report summary` | Show aggregated host stats, OS distribution, recent activity. |
| `python -m netscan report export` | Export hosts (and optionally history) to json/csv/xml/txt/sql. |
| `python -m netscan config ...` | Manage configuration and credentials (supports aliases and dot keys). |
| `python -m netscan database ...` | Maintenance utilities (backup, vacuum, restore). |

### Key Scan Options

- `--range / -r`: IP range to scan (CIDR or single IP, required for `scan network`).
- `--username / -u`: SSH username (optional for network discovery; required for auth/info).
- `--password / -p`: SSH password; omit value to prompt securely and fall back to stored secrets if available.
- `--key-file / -k`: Path to SSH private key.
- `--port / -P`: SSH port (default 22).
- `--threads / -t`: Concurrent workers (1–100, defaults to config `scanning.default_threads`).
- `--timeout / -T`: Socket/SSH timeout in seconds (1–300).
- `--retries / -R`: Number of re-tries for unreachable hosts during network scans (0–10, default from config).
- `--no-nmap`: Skip the nmap pre-scan and force socket-only discovery.
- `--store-db`: Persist info-collection results (complete *and* partial datasets) to the database.

### Report Options Snapshot

- `--filter`: `key=value` filter (`status`, `os`, `ip`, `hostname`, `port` for hosts; similar patterns elsewhere).
- `--format / --Format`: Switch output between table/json/csv/text.
- `--output`: Write report/export to file.
- `--sort`: Sort column (e.g., `last_scan`, `ip_address`).
- `--limit`: Cap the number of rows displayed.

## Database Schema

NetScan uses SQLite to store scan results with the following structure:

- **hosts**: Host information and system details
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