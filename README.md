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
# Create credentials file
cat > credentials.txt << 'EOF'
admin:admin
admin:password
root:root
root:password
ubuntu:ubuntu
EOF

# Run comprehensive scan (does everything in one command)
python -m netscan scan full --range 192.168.1.0/24 --credentials-file credentials.txt
```

### Basic Network Scan

```bash
# Scan a subnet with credentials
python -m netscan scan network --range 192.168.1.0/24 --username admin --password secret

# Scan with multiple credentials
python -m netscan scan network --range 10.0.0.0/16 --multiple-usernames admin,root,user --multiple-passwords admin,password,123456
```

### Configuration Management

```bash
# Set default credentials
python -m netscan config set-credential username admin
python -m netscan config set-credential password

# View current configuration
python -m netscan config show
```

### Generate Reports

```bash
# View all discovered hosts
python -m netscan report hosts --format table

# Filter by OS type
python -m netscan report hosts --filter "os=ubuntu" --format table

# Export to JSON
python -m netscan report export --format json --output results.json
```

## Usage

### Commands

- `scan full` - **Complete workflow**: Discovery → Authentication → Info Collection ⭐
- `scan network` - Discover SSH-enabled hosts
- `scan auth` - Test SSH authentication
- `scan info` - Collect system information
- `report` - Generate reports from stored data
- `config` - Manage configuration settings
- `database` - Database management operations

### Scan Options

- `--range`: IP range to scan (CIDR notation)
- `--username` / `--multiple-usernames`: SSH username(s)
- `--password` / `--multiple-passwords`: SSH password(s)
- `--credentials-file`: File with username:password pairs
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

- **hosts**: Host information, system details, and authentication data
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