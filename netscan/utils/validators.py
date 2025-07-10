"""
Input validation utilities for NetScan

This module provides validation functions for user inputs.
"""

import re
import ipaddress
from typing import Optional, Tuple


def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_ip_range(ip_range: str) -> bool:
    """Validate IP range/CIDR format"""
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        # Try as single IP
        return validate_ip_address(ip_range)


def validate_port(port: int) -> bool:
    """Validate port number"""
    return 1 <= port <= 65535


def validate_hostname(hostname: str) -> bool:
    """Validate hostname format"""
    if not hostname or len(hostname) > 253:
        return False
    
    # Check for valid characters
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    
    allowed = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
    return all(allowed.match(x) for x in hostname.split("."))


def validate_username(username: str) -> bool:
    """Validate SSH username format"""
    if not username or len(username) > 32:
        return False
    
    # Basic validation - alphanumeric, underscore, hyphen
    return re.match(r'^[a-zA-Z0-9_-]+$', username) is not None


def validate_timeout(timeout: int) -> bool:
    """Validate timeout value"""
    return 1 <= timeout <= 300  # 1 second to 5 minutes


def validate_threads(threads: int) -> bool:
    """Validate thread count"""
    return 1 <= threads <= 100


def parse_filter_string(filter_str: str) -> Optional[Tuple[str, str]]:
    """Parse filter string in format 'key=value'"""
    if not filter_str or '=' not in filter_str:
        return None
    
    try:
        key, value = filter_str.split('=', 1)
        return key.strip(), value.strip()
    except ValueError:
        return None


def validate_database_path(path: str) -> bool:
    """Validate database file path"""
    if not path:
        return False
    
    # Check for valid filename characters
    import os
    try:
        # Check if path is valid
        os.path.dirname(path)
        return True
    except:
        return False 