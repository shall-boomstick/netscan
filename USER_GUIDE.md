# NetScan User Guide

## Table of Contents
1. [Overview](#overview)
2. [Recent Enhancements](#recent-enhancements)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Configuration](#configuration)
6. [Scanning Networks](#scanning-networks)
7. [Generating Reports](#generating-reports)
8. [Advanced Usage](#advanced-usage)
9. [Troubleshooting](#troubleshooting)
10. [Examples](#examples)

## Overview

NetScan is a powerful Python CLI tool for discovering and analyzing Linux servers with SSH capability. It provides comprehensive network scanning, system information collection, and detailed reporting capabilities with enterprise-grade features.

### Key Features
- 🔍 **Network Discovery**: Multi-threaded scanning of IP ranges to find SSH-enabled hosts
- 🔐 **Multiple Credentials**: Support for testing multiple username/password combinations
- 📊 **System Analysis**: Detailed system information collection (OS, CPU, memory, disk)
- ⚡ **Optimized Performance**: Fast connection testing with optimized timeouts
- 💾 **Data Persistence**: SQLite database for storing scan results and history
- 📈 **Rich Reporting**: Advanced filtering, sorting, and multiple export formats
- ⚙️ **Configuration Management**: Flexible configuration with secure credential storage
- 🎨 **Beautiful Interface**: Rich CLI with progress bars and formatted output
- 🚀 **Comprehensive Workflow**: Complete analysis in one command (`scan full`)

## Recent Enhancements

### ⭐ New Comprehensive Scan Command
The `scan full` command performs a complete network analysis workflow in a single operation:
- **Network Discovery**: Scans IP ranges for SSH-enabled hosts
- **Authentication Testing**: Tests multiple credentials on discovered hosts
- **System Information Collection**: Gathers detailed system data from authenticated hosts
- **Database Storage**: Stores all results including working credentials

```bash
# Complete analysis in one command
python -m netscan scan full --range 192.168.1.0/24 --credentials-file credentials.txt
```

### 🔐 Enhanced Multiple Credentials Support
- **Credentials File**: Test multiple username:password combinations from a file
- **Command-line Lists**: Specify multiple usernames and passwords directly
- **Flexible Combinations**: Mix single and multiple credential approaches
- **Authentication Tracking**: Store which credentials worked for each host

```bash
# Method 1: Credentials file
python -m netscan scan full --range 192.168.1.0/24 --credentials-file creds.txt

# Method 2: Command-line lists
python -m netscan scan full --range 192.168.1.0/24 \
    --multiple-usernames admin,root,user \
    --multiple-passwords admin,password,123456
```

### ⚡ Optimized Performance
- **Faster Timeouts**: Reduced default timeouts for quicker scanning (3s network, 5s SSH)
- **Improved Concurrency**: Better thread management for high-performance scanning
- **Graceful Fallbacks**: Automatic fallback from nmap to socket scanning
- **Root Privilege Handling**: Clear messaging and automatic privilege detection

```bash
# Fast scanning with optimized defaults
python -m netscan scan full --range 192.168.1.0/24 --credentials-file creds.txt

# Custom performance tuning
python -m netscan scan full --range 192.168.1.0/24 \
    --credentials-file creds.txt \
    --timeout 2 \
    --threads 50
```

### 🗄️ Enhanced Database Schema
- **Authentication Details**: Store working username, auth method, and attempt counts
- **Improved Host Tracking**: Better tracking of authentication success/failure
- **Historical Data**: Maintain scan history with detailed metadata

### 🛡️ Security Improvements
- **Privilege Handling**: Automatic detection and graceful handling of root requirements
- **Secure Credential Storage**: Encrypted storage of sensitive credentials
- **Connection Pooling**: Efficient SSH connection management
- **Error Recovery**: Robust error handling and retry mechanisms

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- nmap (optional, for faster network discovery)

### Install nmap (Optional but Recommended)
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

**Note about nmap privileges:**
- NetScan works without nmap (uses socket scanning)
- Regular users can use nmap's TCP connect scan (`-sT`)
- Advanced nmap features (SYN scan `-sS`) require root privileges
- NetScan automatically handles privilege issues and falls back gracefully

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

### 1. Complete Network Analysis (Recommended)
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

# Or with command-line credentials
python -m netscan scan full \
    --range 192.168.1.0/24 \
    --multiple-usernames admin,root,user \
    --multiple-passwords admin,password,123456
```

### 1b. Individual Steps (Alternative)
```bash
# Step-by-step approach (if you prefer manual control)
python -m netscan scan network --range 192.168.1.0/24 --username admin
python -m netscan scan auth --from-db --username admin --password
python -m netscan scan info --from-db --username admin --password --store-db
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
  - `scan full` - **Complete workflow: Discovery → Authentication → Info Collection** ⭐
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
default_timeout = 3
default_threads = 10
use_nmap = true
max_retries = 3

[ssh]
auth_timeout = 5
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
    --timeout 5 \
    --threads 50 \
    --no-nmap

# Test SSH authentication on discovered hosts
python -m netscan scan auth \
    --from-db \
    --username admin \
    --password \
    --timeout 8 \
    --threads 25

# Collect system information from authenticated hosts
python -m netscan scan info \
    --from-db \
    --username admin \
    --password \
    --store-db
```

### Comprehensive Scan Workflow (Recommended)

The `scan full` command is the **recommended way** to use NetScan. It performs a complete analysis workflow in a single operation: network discovery → credential testing → system information collection → database storage.

#### Workflow Overview
1. **🔍 Network Discovery**: Scans the IP range for hosts with open SSH ports
2. **🔐 Authentication Testing**: Tests all provided credentials on discovered hosts  
3. **📊 System Information**: Collects detailed system info from authenticated hosts
4. **💾 Database Storage**: Stores all results including working credentials
5. **📋 Comprehensive Reporting**: Shows real-time progress and detailed summary

#### Basic Usage
```bash
# Complete scan with credentials file (most efficient)
python -m netscan scan full \
    --range 192.168.1.0/24 \
    --credentials-file credentials.txt

# Complete scan with multiple username/password pairs
python -m netscan scan full \
    --range 192.168.1.0/24 \
    --multiple-usernames admin,root,user \
    --multiple-passwords admin,password,123456

# Complete scan with single credentials
python -m netscan scan full \
    --range 192.168.1.0/24 \
    --username admin \
    --password mypassword

# Scan specific hosts instead of a range
python -m netscan scan full \
    --range 192.168.1.100,192.168.1.101,192.168.1.102 \
    --credentials-file credentials.txt
```

#### Advanced Options
```bash
# High-performance scan with custom settings
python -m netscan scan full \
    --range 10.0.0.0/16 \
    --credentials-file enterprise-creds.txt \
    --timeout 3 \
    --threads 25 \
    --port 2222 \
    --output scan-results.json

# Socket-based scan (without nmap)
python -m netscan scan full \
    --range 192.168.1.0/24 \
    --credentials-file credentials.txt \
    --no-nmap \
    --timeout 2

# Scan without storing in database
python -m netscan scan full \
    --range 192.168.1.0/24 \
    --username admin \
    --password secret \
    --no-store-db \
    --output results-only.json
```

#### Real-time Output Example
```bash
Phase 1: Network Discovery
Scanning range: 192.168.1.0/24
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 254/254 hosts
Nmap scan complete: 5 active SSH hosts found

Phase 2: Authentication Testing  
Testing credentials on 5 hosts
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 5/5 hosts
✓ Authenticated: admin@192.168.1.100 (password)
✓ Authenticated: root@192.168.1.101 (password)
✓ Authenticated: user@192.168.1.102 (password)
✗ Auth failed: 192.168.1.103 (6 attempts)
✗ Auth failed: 192.168.1.104 (6 attempts)

Phase 3: System Information Collection
Collecting system info from 3 authenticated hosts
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 3/3 hosts
✓ Info collected: 192.168.1.100 (admin)
✓ Info collected: 192.168.1.101 (root)
✓ Info collected: 192.168.1.102 (user)

Phase 4: Database Storage
Storing results for 3 hosts
✓ Stored: 192.168.1.100 (admin)
✓ Stored: 192.168.1.101 (root)  
✓ Stored: 192.168.1.102 (user)

┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Phase            ┃ Metric                                        ┃   Count ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ Discovery        │ SSH hosts found                               │       5 │
│ Authentication   │ Hosts tested                                  │       5 │
│                  │ Successful auths                              │       3 │
│                  │ Failed auths                                  │       2 │
│ Info Collection  │ Hosts processed                               │       3 │
│                  │ Successful collections                        │       3 │
│ Database         │ Hosts stored                                  │       3 │
│ Timing           │ Total duration                                │    45.2s │
└──────────────────┴───────────────────────────────────────────────┴─────────┘

Authentication Success Rate: 60.0%
Info Collection Success Rate: 100.0%

Comprehensive scan completed successfully!
```

#### Performance Benefits
- **Single Command**: Complete workflow in one operation
- **Optimized Timeouts**: Fast connection testing (3s network, 5s SSH)
- **Efficient Credential Testing**: Stops on first successful authentication
- **Progress Tracking**: Real-time progress bars for each phase
- **Detailed Reporting**: Comprehensive summary with success rates

### Multiple Credentials Support

NetScan supports testing multiple username/password combinations, which is especially useful in environments with inconsistent credentials across hosts.

#### Method 1: Comma-separated Lists
```bash
# Test multiple username/password pairs
python -m netscan scan auth \
    --hosts 192.168.1.100,192.168.1.101,192.168.1.102 \
    --multiple-usernames admin,root,user \
    --multiple-passwords admin,password,123456 \
    --try-multiple-credentials

# Collect system info with multiple credentials
python -m netscan scan info \
    --from-db \
    --multiple-usernames admin,root,user \
    --multiple-passwords admin,password,123456 \
    --try-multiple-credentials \
    --store-db
```

#### Method 2: Credentials File
```bash
# Create credentials file (credentials.txt)
cat > credentials.txt << 'EOF'
# Common default credentials
admin:admin
admin:password
root:root
root:password
root:toor
administrator:admin
ubuntu:ubuntu
centos:centos
user:user
EOF

# Use credentials file for authentication testing
python -m netscan scan auth \
    --hosts 192.168.1.100,192.168.1.101 \
    --credentials-file credentials.txt \
    --try-multiple-credentials

# Use credentials file for system info collection
python -m netscan scan info \
    --from-db \
    --credentials-file credentials.txt \
    --try-multiple-credentials \
    --store-db
```

#### Method 3: Multiple Usernames with Single Password/Key
```bash
# Try multiple usernames with the same password
python -m netscan scan auth \
    --hosts 192.168.1.100,192.168.1.101 \
    --multiple-usernames admin,root,user,ubuntu \
    --password mypassword \
    --try-multiple-credentials

# Try multiple usernames with SSH key
python -m netscan scan auth \
    --hosts 192.168.1.100,192.168.1.101 \
    --multiple-usernames admin,root,user \
    --key-file ~/.ssh/id_rsa \
    --try-multiple-credentials
```

#### Multiple Credentials Output
When using multiple credentials, NetScan will:
- Try each credential combination until one succeeds
- Show which credentials worked for each host
- Display detailed attempt counts for failed connections
- Continue with working credentials for system info collection
- Store authentication details in the database

```bash
Testing multiple credentials on 3 hosts...
✓ SSH connected: admin@192.168.1.100:22 (password)
✓ SSH connected: root@192.168.1.101:22 (password)  
✗ SSH failed: 192.168.1.102:22 - All credentials failed (6 attempts)

Summary:
Successful connections: 2
Failed connections: 1
Success rate: 66.7%
```

### Enhanced Database Storage
NetScan now stores detailed authentication information:
- **Working Username**: The username that successfully authenticated
- **Auth Method**: Password or key-based authentication
- **Attempt Count**: Number of credential combinations tried
- **Auth Status**: Success/failure status for each host

```bash
# View hosts with authentication details
python -m netscan report hosts --format table

# Example output showing auth details:
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ IP Address     ┃ Hostname       ┃ Status   ┃ Auth Details          ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ 192.168.1.100  │ web-server-01  │ active   │ admin (password)      │
│ 192.168.1.101  │ db-server-01   │ active   │ root (password)       │
│ 192.168.1.102  │ app-server-01  │ inactive │ Failed (6 attempts)   │
└────────────────┴────────────────┴──────────┴───────────────────────┘
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

#### 1. Nmap Permission Issues
```bash
# Issue: "You requested a scan type which requires root privileges"
# Solution: NetScan automatically falls back to TCP connect scan (-sT) which doesn't require root

# The comprehensive scan automatically handles privilege issues gracefully:
python -m netscan scan full --range 192.168.1.0/24 --credentials-file creds.txt

# If you want to use advanced nmap features (SYN scan), run with sudo:
sudo python -m netscan scan full --range 192.168.1.0/24 --credentials-file creds.txt

# Or disable nmap entirely (uses socket scanning):
python -m netscan scan full --range 192.168.1.0/24 --credentials-file creds.txt --no-nmap

# NetScan automatically detects privilege issues and provides clear messaging
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
# Solution: NetScan now uses optimized timeouts by default (3s for scanning, 5s for SSH)
# For even faster scanning, reduce timeouts further:
python -m netscan config set scanning.timeout 2
python -m netscan config set ssh.auth_timeout 3

# Increase concurrency for high-performance scanning
python -m netscan config set scanning.threads 50

# Use the comprehensive scan with optimized settings
python -m netscan scan full \
    --range 192.168.1.0/24 \
    --credentials-file creds.txt \
    --timeout 2 \
    --threads 50

# For very large networks, use socket scanning (faster than nmap for basic discovery)
python -m netscan scan full \
    --range 192.168.1.0/24 \
    --credentials-file creds.txt \
    --no-nmap \
    --timeout 1
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

#### 5. Multiple Credentials Issues
```bash
# Issue: Multiple credentials format errors
# Solution: Ensure proper format in credentials file
cat > credentials.txt << 'EOF'
# Comments start with #
username1:password1
username2:password2
EOF

# Issue: Mismatched username/password counts
# Solution: Ensure equal number of usernames and passwords
python -m netscan scan auth \
    --hosts 192.168.1.100 \
    --multiple-usernames "admin,root,user" \
    --multiple-passwords "pass1,pass2,pass3" \
    --try-multiple-credentials

# Issue: Too many failed authentication attempts
# Solution: Use more targeted credential lists or reduce timeout
python -m netscan scan auth \
    --credentials-file small-creds.txt \
    --timeout 3 \
    --try-multiple-credentials
```

#### 6. Performance with Multiple Credentials
```bash
# Issue: Multiple credentials testing is slow
# Solution: Optimize credential lists and use faster timeouts
# Use only likely credentials
echo -e "admin:admin\nroot:root\nubuntu:ubuntu" > quick-creds.txt

# Use faster timeouts for bulk testing
python -m netscan scan auth \
    --from-db \
    --credentials-file quick-creds.txt \
    --timeout 3 \
    --threads 20 \
    --try-multiple-credentials
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

### Example 1: Complete Network Analysis
```bash
# Create comprehensive credentials file
cat > office-creds.txt << 'EOF'
# Default accounts
admin:admin
admin:password
root:root
root:password
root:toor

# Service accounts  
ubuntu:ubuntu
centos:centos
user:user
EOF

# Run complete analysis in one command
python -m netscan scan full \
    --range 192.168.1.0/24 \
    --credentials-file office-creds.txt \
    --timeout 5 \
    --threads 15 \
    --output complete-analysis.json

# View discovered and analyzed hosts
python -m netscan report hosts --status active

# Export comprehensive results
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

### Example 3: Multiple Credentials Discovery
```bash
# Create comprehensive credentials file for mixed environments
cat > comprehensive-creds.txt << 'EOF'
# Default accounts
admin:admin
admin:password
administrator:admin
root:root
root:password
root:toor

# Service accounts
ubuntu:ubuntu
centos:centos
debian:debian
oracle:oracle
postgres:postgres

# Common weak passwords
admin:123456
admin:admin123
root:123456
user:password
guest:guest
EOF

# Test authentication across discovered hosts
python -m netscan scan network --range 192.168.1.0/24 --username admin
python -m netscan scan auth \
    --from-db \
    --credentials-file comprehensive-creds.txt \
    --try-multiple-credentials \
    --timeout 5 \
    --threads 15

# Collect system information from successfully authenticated hosts
python -m netscan scan info \
    --from-db \
    --credentials-file comprehensive-creds.txt \
    --try-multiple-credentials \
    --store-db

# Generate report showing which credentials worked
python -m netscan report hosts --format table
```

### Example 4: Monitoring and Alerting
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

### 🚀 Performance Optimization
1. **Use the Comprehensive Scan**: The `scan full` command is optimized for performance
2. **Optimize Timeouts**: Use shorter timeouts for faster scanning (2-3s for network, 3-5s for SSH)
3. **Increase Concurrency**: Use higher thread counts (25-50) for large networks
4. **Socket Scanning**: Use `--no-nmap` for faster basic discovery on large networks
5. **Targeted Credentials**: Use focused credential lists to reduce authentication time

```bash
# High-performance scanning example
python -m netscan scan full \
    --range 192.168.1.0/24 \
    --credentials-file focused-creds.txt \
    --timeout 2 \
    --threads 50 \
    --no-nmap
```

### 🔐 Security Best Practices
1. **SSH Key Authentication**: Use SSH keys when possible for better security
2. **Secure Credential Storage**: Use NetScan's encrypted credential storage
3. **Limited Scan Ranges**: Only scan necessary network segments
4. **Minimal Privileges**: Run with minimal required privileges
5. **Regular Updates**: Keep NetScan and dependencies updated

### 📊 Data Management
1. **Regular Backups**: Schedule database backups
2. **History Cleanup**: Clean up old scan history periodically
3. **Data Export**: Export critical data to external systems
4. **Database Monitoring**: Monitor database size and performance
5. **Version Control**: Track configuration changes

### 🔍 Monitoring and Alerting
1. **Automated Scanning**: Set up scheduled scans during off-peak hours
2. **Change Detection**: Configure alerts for new/missing hosts
3. **Integration**: Integrate with existing monitoring systems
4. **Performance Tracking**: Monitor scan performance and success rates
5. **Capacity Planning**: Track network growth and resource usage

### ⚡ Performance Tuning Guide

#### For Small Networks (< 100 hosts)
```bash
python -m netscan scan full \
    --range 192.168.1.0/24 \
    --credentials-file creds.txt \
    --timeout 3 \
    --threads 10
```

#### For Medium Networks (100-1000 hosts)
```bash
python -m netscan scan full \
    --range 10.0.0.0/16 \
    --credentials-file creds.txt \
    --timeout 2 \
    --threads 25
```

#### For Large Networks (> 1000 hosts)
```bash
python -m netscan scan full \
    --range 172.16.0.0/12 \
    --credentials-file creds.txt \
    --timeout 1 \
    --threads 50 \
    --no-nmap
```

#### For Enterprise Environments
```bash
# Configure for enterprise scanning
python -m netscan config set scanning.threads 100
python -m netscan config set scanning.timeout 15
python -m netscan config set ssh.connection_pool_size 50

# Run comprehensive scan
python -m netscan scan full \
    --range "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" \
    --credentials-file enterprise-creds.txt
```

## Quick Reference

### Common Commands
```bash
# Complete network analysis (recommended)
python -m netscan scan full --range 192.168.1.0/24 --credentials-file creds.txt

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
python -m netscan config set-credential username admin
python -m netscan config set-credential password
```

### Command Patterns
- Complete analysis: `scan full --range <IP_RANGE> --credentials-file <FILE>`
- Network discovery: `scan network --range <IP_RANGE> --username <USER>`
- Authentication test: `scan auth --from-db --username <USER> [--password|--key-file]`
- Info collection: `scan info --from-db --username <USER> --store-db`
- Report generation: `report <TYPE> [--format FORMAT] [--output FILE]`
- Configuration: `config <OPERATION> [OPTIONS]`

For more information, see the [Development Plan](DEVELOPMENT_PLAN.md) and project documentation. 