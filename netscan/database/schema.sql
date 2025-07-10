-- NetScan Database Schema
-- SQLite database schema for storing scan results and configuration

-- Hosts table: stores information about discovered hosts
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    hostname TEXT,
    ssh_port INTEGER DEFAULT 22,
    status TEXT CHECK(status IN ('active', 'inactive', 'error')) DEFAULT 'active',
    os_info TEXT,
    kernel_version TEXT,
    uptime TEXT,
    cpu_info TEXT,
    memory_total INTEGER,
    memory_used INTEGER,
    disk_usage TEXT,
    last_scan TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scan history table: stores historical scan records
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER,
    scan_type TEXT,
    result TEXT,
    error_message TEXT,
    scan_duration REAL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
);

-- Configuration table: stores application settings
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_hosts_ip_address ON hosts(ip_address);
CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);
CREATE INDEX IF NOT EXISTS idx_hosts_last_scan ON hosts(last_scan);
CREATE INDEX IF NOT EXISTS idx_scan_history_host_id ON scan_history(host_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_config_key ON config(key); 