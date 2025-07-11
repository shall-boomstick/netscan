# NetScan User Guide

## Table of Contents
1. [Overview](#overview)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Configuration](#configuration)
5. [Scanning Networks](#scanning-networks)
6. [Generating Reports](#generating-reports)
7. [Advanced Usage](#advanced-usage)
8. [Troubleshooting](#troubleshooting)
9. [Examples](#examples)

## Overview

NetScan is a powerful Python CLI tool for discovering and analyzing Linux servers with SSH capability. It provides comprehensive network scanning, system information collection, and detailed reporting capabilities.

### Key Features
- 🔍 **Network Discovery**: Multi-threaded scanning of IP ranges to find SSH-enabled hosts
- 📊 **System Analysis**: Detailed system information collection (OS, CPU, memory, disk)
- 💾 **Data Persistence**: SQLite database for storing scan results and history
- 📈 **Rich Reporting**: Advanced filtering, sorting, and multiple export formats
- ⚙️ **Configuration Management**: Flexible configuration with secure credential storage
- 🎨 **Beautiful Interface**: Rich CLI with progress bars and formatted output

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- nmap (for advanced network discovery)

### Install nmap (Required)
```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install nmap

# CentOS/RHEL/Fedora
sudo dnf install nmap  # or sudo yum install nmap

# macOS
brew install nmap

# Windows
# Download from https://nmap.org/download.html
```

### Install NetScan
```bash
# Clone the repository
git clone <repository-url>
cd netscan

# Create virtual environment
python -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -m netscan --helppytho
```

## Quick Start

### 1. First Scan
```bash
# Basic network scan
python -m netscan scan network --range 192.168.1.0/24 --username admin

# Scan with password (will prompt securely) 
python -m netscan scan network --range 10.0.0.0/16 --username root --password

# Scan specific hosts
python -m netscan scan network --range 192.168.1.10,192.168.1.20,192.168.1.30 --username admin
```

### 2. View Results
```bash
# List all discovered hosts
python -m netscan report hosts

# Show summary statistics
python -m netscan report summary

# Export results
python -m netscan report export --format json --output results.json
```

### 3. Configuration
```bash
# Set default credentials
python -m netscan config set-credential username admin
python -m netscan config set-credential password

# Configure scanning settings
python -m netscan config set scanning.threads 20
python -m netscan config set scanning.timeout 10
```

## CLI Command Structure

NetScan uses a hierarchical command structure with subcommands:

### Main Command Groups
- **scan** - Network scanning operations
  - `scan network` - Discover hosts with SSH capability
  - `scan auth` - Test SSH authentication on hosts
  - `scan info` - Collect detailed system information
- **report** - Generate and export reports
  - `report hosts` - List discovered hosts
  - `report summary` - Generate summary statistics
  - `report export` - Export data to files
  - `report history` - View scan history
- **config** - Configuration management
  - `config set` - Set configuration values
  - `config show` - Display current configuration
  - `config credentials` - Manage stored credentials
- **database** - Database operations
  - `database init` - Initialize database
  - `database backup` - Create database backup
  - `database restore` - Restore from backup

### Getting Help
```bash
# General help
python -m netscan --help

# Help for specific command groups
python -m netscan scan --help
python -m netscan report --help
python -m netscan config --help

# Help for specific commands
python -m netscan scan network --help
python -m netscan report hosts --help
```

## Configuration

NetScan supports flexible configuration from multiple sources:

### Configuration Sources (Priority Order)
1. **Command line arguments** (highest priority)
2. **Environment variables** (prefix: `NETSCAN_`)
3. **Configuration file** (`~/.netscan/config.conf`)
4. **Database settings**
5. **Default values** (lowest priority)

### Configuration File
Location: `~/.netscan/config.conf`

```ini
[scanning]
default_port = 22
default_timeout = 5
default_threads = 10
use_nmap = true
max_retries = 3

[ssh]
auth_timeout = 10
key_discovery = true
preferred_auth = key
connection_pool_size = 20

[database]
path = netscan.db
backup_enabled = true
backup_interval = 7
vacuum_enabled = true

[reporting]
default_format = table
max_results = 1000
export_timestamp = true
include_metadata = true

[logging]
level = INFO
file_enabled = false
file_path = netscan.log
max_size = 10485760
backup_count = 5
```

### Environment Variables
```bash
export NETSCAN_DEFAULT_TIMEOUT=10
export NETSCAN_DEFAULT_THREADS=20
export NETSCAN_USE_NMAP=true
export NETSCAN_LOG_LEVEL=DEBUG
```

### Configuration Commands
```bash
# View current configuration
python -m netscan config show

# Set configuration values
python -m netscan config set scanning.timeout 15
python -m netscan config set scanning.threads 25

# Export configuration
python -m netscan config export-config --output my-config.conf

# Import configuration
python -m netscan config import-config --input my-config.conf

# Reset to defaults
python -m netscan config reset
```

### Credential Management
```bash
# Set credentials (encrypted storage)
python -m netscan config set-credential username admin
python -m netscan config set-credential password

# List stored credentials
python -m netscan config list-credentials

# Delete credentials
python -m netscan config delete-credential password
```

## Scanning Networks

### Basic Scanning
```bash
# Scan IP range with username/password
python -m netscan scan network --range 192.168.1.0/24 --username admin --password secret

# Scan with SSH key authentication  
python -m netscan scan auth --hosts $(python -m netscan scan network --range 10.0.0.0/8 --username admin | grep active) --username admin --key-file ~/.ssh/id_rsa

# Scan specific IPs
python -m netscan scan network --range 192.168.1.10,192.168.1.20 --username root
```

### Advanced Scanning Options
```bash
# Customize scanning parameters
python -m netscan scan network \
    --range 172.16.0.0/12 \
    --username admin \
    --port 2222 \
    --timeout 10 \
    --threads 50 \
    --no-nmap

# Test SSH authentication on discovered hosts
python -m netscan scan auth \
    --from-db \
    --username admin \
    --password \
    --timeout 30 \
    --threads 25

# Collect system information from authenticated hosts
python -m netscan scan info \
    --from-db \
    --username admin \
    --password \
    --store-db
```

### Scan Output
During scanning, you'll see:
- Real-time progress bar
- Host discovery status
- SSH connection attempts
- System information collection progress
- Error handling and retry attempts

```
Scanning Network Range: 192.168.1.0/24
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 254/254 hosts

Discovered Hosts:
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┓
┃ IP Address     ┃ Hostname       ┃ Status   ┃ SSH Port ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━┩
│ 192.168.1.100  │ server01       │ active   │ 22       │
│ 192.168.1.101  │ server02       │ active   │ 22       │
│ 192.168.1.150  │ router         │ inactive │ -        │
└────────────────┴────────────────┴──────────┴──────────┘

Scan completed: 2 active hosts found
```

## Generating Reports

### Host Reports
```bash
# Basic host listing
python -m netscan report hosts

# Filter by status
python -m netscan report hosts --status active
python -m netscan report hosts --status inactive

# Filter by OS
python -m netscan report hosts --os-filter ubuntu
python -m netscan report hosts --os-filter "CentOS 7"

# Filter by IP range
python -m netscan report hosts --ip-filter 192.168.1.0/24

# Sort and limit results
python -m netscan report hosts --sort-by last_scan --limit 50

# Different output formats
python -m netscan report hosts --format table    # Default
python -m netscan report hosts --format json
python -m netscan report hosts --format csv
```

### Summary Reports
```bash
# Overview statistics
python -m netscan report summary

# Detailed summary with charts
python -m netscan report summary --detailed

# Summary for specific time period
python -m netscan report summary --since "2024-01-01"
python -m netscan report summary --since "7 days ago"
```

### Export Reports
```bash
# Export to JSON
python -m netscan report export --format json --output hosts.json

# Export to CSV
python -m netscan report export --format csv --output hosts.csv

# Export to XML
python -m netscan report export --format xml --output hosts.xml

# Export with filters
python -m netscan report export \
    --format json \
    --output active-hosts.json \
    --status active \
    --os-filter ubuntu

# Export scan history
python -m netscan report history --format json --output scan-history.json
```

### Report Output Examples

**Table Format:**
```
                           Discovered Hosts
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ IP Address     ┃ Hostname       ┃ Status   ┃ OS Info               ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ 192.168.1.100  │ web-server-01  │ active   │ Ubuntu 22.04.3 LTS   │
│ 192.168.1.101  │ db-server-01   │ active   │ CentOS Linux 7        │
│ 192.168.1.102  │ app-server-01  │ active   │ Debian GNU/Linux 11   │
└────────────────┴────────────────┴──────────┴───────────────────────┘
```

**Summary Report:**
```
NetScan Summary Report
==============================
Generated: 2024-07-10 10:30:00

STATISTICS
----------
Total Hosts: 25
Active Hosts: 18
Inactive Hosts: 5
Error Hosts: 2
Success Rate: 72.0%

OS DISTRIBUTION
---------------
Ubuntu: 8 (44.4%)
CentOS: 6 (33.3%)
Debian: 4 (22.2%)

MEMORY USAGE SUMMARY
--------------------
Hosts with memory data: 18
Total memory across all hosts: 147,456 MB
Used memory across all hosts: 89,234 MB
Average memory usage: 60.5%
```

## Advanced Usage

### Database Management
```bash
# Database operations
python -m netscan database init       # Initialize database
python -m netscan database backup --output backup.db
python -m netscan database restore --input backup.db
python -m netscan database vacuum    # Optimize database

# Host management
python -m netscan hosts delete --ip 192.168.1.100
python -m netscan hosts update --ip 192.168.1.101 --hostname new-name
```

### Scheduled Scanning
```bash
# Create a scan script for cron
cat > daily-scan.sh << 'EOF'
#!/bin/bash
cd /path/to/netscan
source venv/bin/activate
python -m netscan scan network --range 192.168.1.0/24 --username admin
python -m netscan report export --format json --output /var/log/netscan/daily-$(date +%Y%m%d).json
EOF

chmod +x daily-scan.sh

# Add to crontab (daily at 2 AM)
echo "0 2 * * * /path/to/daily-scan.sh" | crontab -
```

### Integration with Other Tools
```bash
# Export for monitoring systems
python -m netscan report export --format json | jq '.hosts[] | select(.status=="active")'

# Generate Ansible inventory
python -m netscan report hosts --format json | \
    jq -r '.hosts[] | select(.status=="active") | "\(.hostname) ansible_host=\(.ip_address)"'

# Generate Nagios configuration
python -m netscan report hosts --status active --format csv | \
    awk -F',' 'NR>1 {print "define host{"; print "  host_name " $2; print "  address " $1; print "}"}'
```

### Custom Filtering and Queries
```bash
# Complex filtering
python -m netscan report hosts \
    --status active \
    --os-filter "Ubuntu.*22.04" \
    --memory-min 8192 \
    --last-scan-within "24 hours"

# Search hosts
python -m netscan hosts search --term "web-server"
python -m netscan hosts search --term "192.168.1"

# Host statistics
python -m netscan report statistics --group-by os_info
python -m netscan report statistics --group-by status
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied Errors
```bash
# Issue: Cannot bind to privileged ports
# Solution: Use sudo for nmap operations or higher port numbers
sudo python -m netscan scan network --range 192.168.1.0/24 --username admin

# Or disable nmap
python -m netscan scan network --range 192.168.1.0/24 --username admin --no-nmap
```

#### 2. SSH Connection Failures
```bash
# Issue: SSH authentication failures
# Solution: Check credentials and SSH key permissions
python -m netscan config set-credential username correct-username
python -m netscan config set-credential password

# For SSH keys
chmod 600 ~/.ssh/id_rsa
python -m netscan scan auth --from-db --username admin --key-file ~/.ssh/id_rsa
```

#### 3. Slow Scanning Performance
```bash
# Issue: Scanning takes too long
# Solution: Adjust timeout and thread settings
python -m netscan config set scanning.threads 50
python -m netscan config set scanning.timeout 3

# Or use command line options
python -m netscan scan network --range 192.168.1.0/24 --threads 50 --timeout 3
```

#### 4. Database Issues
```bash
# Issue: Database corruption
# Solution: Backup and restore database
python -m netscan database backup --output backup.db
rm netscan.db
python -m netscan database restore --input backup.db

# Or reinitialize
rm netscan.db
python -m netscan database init
```

### Debug Mode
```bash
# Enable verbose logging
python -m netscan --debug scan network --range 192.168.1.0/24 --username admin

# Or set logging level
export NETSCAN_LOG_LEVEL=DEBUG
python -m netscan scan network --range 192.168.1.0/24 --username admin
```

### Log Files
```bash
# Enable file logging
python -m netscan config set logging.file_enabled true
python -m netscan config set logging.file_path /var/log/netscan.log

# View logs
tail -f /var/log/netscan.log
```

## Examples

### Example 1: Basic Network Discovery
```bash
# Discover hosts in local network
python -m netscan scan network --range 192.168.1.0/24 --username admin --password

# View discovered hosts
python -m netscan report hosts --status active

# Export to JSON for further processing
python -m netscan report export --format json --output network-inventory.json
```

### Example 2: Enterprise Network Scan
```bash
# Configure for enterprise scanning
python -m netscan config set scanning.threads 100
python -m netscan config set scanning.timeout 15
python -m netscan config set ssh.connection_pool_size 50

# Set up credentials
python -m netscan config set-credential username enterprise-admin
python -m netscan config set-credential password

# Scan multiple subnets
python -m netscan scan network --range "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

# Generate comprehensive report
python -m netscan report summary --detailed > enterprise-report.txt
python -m netscan report export --format csv --output enterprise-inventory.csv
```

### Example 3: Monitoring and Alerting
```bash
# Create monitoring script
cat > monitor-network.sh << 'EOF'
#!/bin/bash
cd /opt/netscan
source venv/bin/activate

# Scan network
python -m netscan scan network --range 192.168.1.0/24 --username monitor

# Check for new hosts
NEW_HOSTS=$(python -m netscan report hosts --since "1 hour ago" --format json | jq '.hosts | length')

if [ "$NEW_HOSTS" -gt 0 ]; then
    echo "Alert: $NEW_HOSTS new hosts discovered"
    python -m netscan report hosts --since "1 hour ago" --format table
    # Send alert email, Slack notification, etc.
fi

# Check for offline hosts
OFFLINE_HOSTS=$(python -m netscan report hosts --status inactive --format json | jq '.hosts | length')

if [ "$OFFLINE_HOSTS" -gt 5 ]; then
    echo "Warning: $OFFLINE_HOSTS hosts are offline"
    # Send notification
fi
EOF

chmod +x monitor-network.sh
```

### Example 4: Integration with Configuration Management
```bash
# Generate Ansible inventory
python -m netscan report hosts --status active --format json | \
jq -r '.hosts[] | "\(.hostname) ansible_host=\(.ip_address) ansible_user=admin"' > inventory.ini

# Generate Puppet node definitions
python -m netscan report hosts --status active --format json | \
jq -r '.hosts[] | "node \"\(.hostname)\" { include base_config }"' > nodes.pp

# Generate SSH config
python -m netscan report hosts --status active --format json | \
jq -r '.hosts[] | "Host \(.hostname)\n  HostName \(.ip_address)\n  User admin\n"' > ~/.ssh/config.d/netscan
```

### Example 5: Performance Monitoring
```bash
# Set up regular scanning with performance tracking
python -m netscan scan network --range 192.168.1.0/24 --username admin

# Generate performance report
python -m netscan report performance --time-range "last 30 days"

# Export performance data for graphing
python -m netscan report export --format json --include-performance --output perf-data.json

# Create performance dashboard data
python -m netscan report statistics --group-by performance --output dashboard.json
```

## Best Practices

1. **Security**:
   - Use SSH key authentication when possible
   - Store credentials securely using NetScan's encrypted storage
   - Limit scan ranges to necessary networks
   - Run with minimal required privileges

2. **Performance**:
   - Adjust thread count based on network capacity
   - Use appropriate timeouts for your environment
   - Enable nmap for faster network discovery
   - Schedule scans during off-peak hours

3. **Data Management**:
   - Regular database backups
   - Clean up old scan history periodically
   - Export critical data to external systems
   - Monitor database size and performance

4. **Monitoring**:
   - Set up automated scanning schedules
   - Configure alerts for new/missing hosts
   - Integrate with existing monitoring systems
   - Track performance and capacity trends

## Quick Reference

### Common Commands
```bash
# Discover hosts in network
python -m netscan scan network --range 192.168.1.0/24 --username admin

# Test SSH authentication
python -m netscan scan auth --from-db --username admin --password

# Collect system information
python -m netscan scan info --from-db --username admin --store-db

# List active hosts
python -m netscan report hosts --status active

# Export to JSON
python -m netscan report export --format json --output hosts.json

# View configuration
python -m netscan config show

# Set default credentials
python -m netscan config credentials --interactive
```

### Command Patterns
- Network discovery: `scan network --range <IP_RANGE> --username <USER>`
- Authentication test: `scan auth --from-db --username <USER> [--password|--key-file]`
- Info collection: `scan info --from-db --username <USER> --store-db`
- Report generation: `report <TYPE> [--format FORMAT] [--output FILE]`
- Configuration: `config <OPERATION> [OPTIONS]`

For more information, see the [Development Plan](DEVELOPMENT_PLAN.md) and project documentation. 