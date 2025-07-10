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

### Basic Network Scan

```bash
# Scan a subnet with credentials
netscan scan --range 192.168.1.0/24 --username admin --password secret

# Scan with custom SSH port
netscan scan --range 10.0.0.0/16 --username root --port 2222
```

### Configuration Management

```bash
# Set default credentials
netscan config --set-username admin --set-password secret

# View current configuration
netscan config --show
```

### Generate Reports

```bash
# View all discovered hosts
netscan report --format table

# Filter by OS type
netscan report --filter "os=ubuntu" --format table

# Export to JSON
netscan report --format json --output results.json
```

## Usage

### Commands

- `scan` - Discover and analyze SSH-enabled hosts
- `report` - Generate reports from stored data
- `config` - Manage configuration settings
- `database` - Database management operations

### Scan Options

- `--range`: IP range to scan (CIDR notation)
- `--username`: SSH username
- `--password`: SSH password
- `--port`: SSH port (default: 22)
- `--threads`: Number of concurrent threads
- `--timeout`: Connection timeout in seconds

### Report Options

- `--filter`: Filter results (e.g., "os=ubuntu", "status=active")
- `--format`: Output format (table, json, csv)
- `--output`: Output file path
- `--sort`: Sort by field

## Database Schema

NetScan uses SQLite to store scan results with the following structure:

- **hosts**: Host information and system details
- **scan_history**: Historical scan records
- **config**: Application configuration

## Development

See [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) for detailed architecture and development information.

### Running Tests

```bash
python -m pytest tests/
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