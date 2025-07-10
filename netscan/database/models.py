"""
Database models for NetScan

This module defines the SQLAlchemy models for the NetScan database.
"""

from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, Text, CheckConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()


class Host(Base):
    """Host model for storing discovered host information"""
    
    __tablename__ = 'hosts'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)  # IPv4/IPv6
    hostname = Column(String(255))
    ssh_port = Column(Integer, default=22)
    status = Column(String(20), default='active', index=True)
    os_info = Column(Text)
    kernel_version = Column(String(100))
    uptime = Column(String(100))
    cpu_info = Column(Text)
    memory_total = Column(Integer)  # in MB
    memory_used = Column(Integer)   # in MB
    disk_usage = Column(Text)       # JSON string for disk usage info
    last_scan = Column(DateTime, default=datetime.utcnow, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan_history = relationship("ScanHistory", back_populates="host", cascade="all, delete-orphan")
    
    # Constraints
    __table_args__ = (
        CheckConstraint("status IN ('active', 'inactive', 'error')", name='check_status'),
    )
    
    def __repr__(self):
        return f"<Host(ip_address='{self.ip_address}', hostname='{self.hostname}', status='{self.status}')>"
    
    def to_dict(self):
        """Convert host object to dictionary"""
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'ssh_port': self.ssh_port,
            'status': self.status,
            'os_info': self.os_info,
            'kernel_version': self.kernel_version,
            'uptime': self.uptime,
            'cpu_info': self.cpu_info,
            'memory_total': self.memory_total,
            'memory_used': self.memory_used,
            'disk_usage': self.disk_usage,
            'last_scan': self.last_scan.isoformat() if self.last_scan else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class ScanHistory(Base):
    """Scan history model for storing scan records"""
    
    __tablename__ = 'scan_history'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey('hosts.id', ondelete='CASCADE'), nullable=False, index=True)
    scan_type = Column(String(50))  # 'network', 'ssh', 'info'
    result = Column(Text)           # JSON string for scan results
    error_message = Column(Text)
    scan_duration = Column(Float)   # in seconds
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    host = relationship("Host", back_populates="scan_history")
    
    def __repr__(self):
        return f"<ScanHistory(host_id={self.host_id}, scan_type='{self.scan_type}', timestamp='{self.timestamp}')>"
    
    def to_dict(self):
        """Convert scan history object to dictionary"""
        return {
            'id': self.id,
            'host_id': self.host_id,
            'scan_type': self.scan_type,
            'result': self.result,
            'error_message': self.error_message,
            'scan_duration': self.scan_duration,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
        }


class Config(Base):
    """Configuration model for storing application settings"""
    
    __tablename__ = 'config'
    
    key = Column(String(100), primary_key=True)
    value = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<Config(key='{self.key}', value='{self.value}')>"
    
    def to_dict(self):
        """Convert config object to dictionary"""
        return {
            'key': self.key,
            'value': self.value,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        } 