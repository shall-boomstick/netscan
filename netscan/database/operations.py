"""
Database operations for NetScan

This module provides CRUD operations and database management functions.
"""

import os
from typing import List, Optional, Dict, Any
from sqlalchemy import create_engine, text, or_
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import IntegrityError, OperationalError, DatabaseError as SQLDatabaseError
from datetime import datetime, timedelta
import json

from .models import Base, Host, ScanHistory, Config as ConfigModel
from ..utils.logging import get_logger, get_database_logger, LoggingContext
from ..utils.error_handling import (
    DatabaseError, retry_operation, RetryConfig, GracefulErrorHandler
)

logger = get_logger("database")
db_logger = get_database_logger()


class DatabaseManager:
    """Database manager class for NetScan"""
    
    def __init__(self, database_path: str = "netscan.db"):
        self.database_path = database_path
        self.engine = None
        self.SessionLocal = None
        self.init_database()
    
    def init_database(self):
        """Initialize database connection and create tables"""
        with LoggingContext(logger, "Database initialization"):
            try:
                database_url = f"sqlite:///{self.database_path}"
                logger.info(f"Initializing database at: {self.database_path}")
                
                self.engine = create_engine(
                    database_url,
                    connect_args={"check_same_thread": False},
                    echo=False
                )
                self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
                
                # Create tables
                Base.metadata.create_all(bind=self.engine)
                logger.info("Database tables created successfully")
                
            except Exception as e:
                logger.error(f"Failed to initialize database: {e}")
                raise DatabaseError(f"Database initialization failed: {e}")
    
    def get_session(self) -> Session:
        """Get database session"""
        return self.SessionLocal()
    
    def close(self):
        """Close database connection"""
        if self.engine:
            self.engine.dispose()
    
    # Host operations
    @retry_operation(RetryConfig(max_attempts=3, retriable_exceptions=[OperationalError]))
    def create_host(self, host_data: Dict[str, Any]) -> Host:
        """Create a new host record"""
        operation = f"create_host({host_data.get('ip_address', 'unknown')})"
        
        with GracefulErrorHandler(operation, logger):
            with self.get_session() as session:
                try:
                    db_logger.log_transaction_start("create_host")
                    start_time = datetime.now()
                    ip_address = host_data.get('ip_address')
                    
                    if not ip_address:
                        raise DatabaseError("Host data must include 'ip_address'")
                    
                    existing_host = session.query(Host).filter(Host.ip_address == ip_address).first()
                    
                    if existing_host:
                        for key, value in host_data.items():
                            if hasattr(existing_host, key) and value is not None:
                                setattr(existing_host, key, value)
                        existing_host.last_scan = datetime.utcnow()
                        session.commit()
                        session.refresh(existing_host)
                        
                        duration = (datetime.now() - start_time).total_seconds()
                        db_logger.log_transaction_commit("create_host(update)", duration)
                        logger.debug(f"Updated existing host: {existing_host.ip_address}")
                        
                        return existing_host
                    
                    host = Host(**host_data)
                    session.add(host)
                    session.commit()
                    session.refresh(host)
                    
                    duration = (datetime.now() - start_time).total_seconds()
                    db_logger.log_transaction_commit("create_host", duration)
                    logger.debug(f"Created new host: {host.ip_address}")
                    
                    return host
                    
                except IntegrityError as e:
                    session.rollback()
                    db_logger.log_transaction_rollback("create_host", f"Integrity constraint: {e}")
                    logger.debug(f"Host {host_data['ip_address']} already exists, updating instead")
                    # Host already exists, update it
                    return self.update_host_by_ip(host_data['ip_address'], host_data)
                    
                except Exception as e:
                    session.rollback()
                    db_logger.log_transaction_rollback("create_host", str(e))
                    raise DatabaseError(f"Failed to create host {host_data.get('ip_address', 'unknown')}: {e}")
    
    def get_host_by_ip(self, ip_address: str) -> Optional[Host]:
        """Get host by IP address"""
        with self.get_session() as session:
            return session.query(Host).filter(Host.ip_address == ip_address).first()
    
    def get_host_by_id(self, host_id: int) -> Optional[Host]:
        """Get host by ID"""
        with self.get_session() as session:
            return session.query(Host).filter(Host.id == host_id).first()
    
    def update_host_by_ip(self, ip_address: str, update_data: Dict[str, Any]) -> Optional[Host]:
        """Update host by IP address"""
        with self.get_session() as session:
            host = session.query(Host).filter(Host.ip_address == ip_address).first()
            if host:
                for key, value in update_data.items():
                    if hasattr(host, key):
                        setattr(host, key, value)
                host.last_scan = datetime.utcnow()
                session.commit()
                session.refresh(host)
                return host
            return None
    
    def delete_host(self, host_id: int) -> bool:
        """Delete host by ID"""
        with self.get_session() as session:
            host = session.query(Host).filter(Host.id == host_id).first()
            if host:
                session.delete(host)
                session.commit()
                return True
            return False
    
    def get_all_hosts(self, status: Optional[str] = None) -> List[Host]:
        """Get all hosts, optionally filtered by status"""
        with self.get_session() as session:
            query = session.query(Host)
            if status:
                query = query.filter(Host.status == status)
            return query.all()
    
    def search_hosts(self, search_term: str) -> List[Host]:
        """Search hosts by IP address, hostname, or OS info"""
        with self.get_session() as session:
            return session.query(Host).filter(
                or_(
                    Host.ip_address.like(f"%{search_term}%"),
                    Host.hostname.like(f"%{search_term}%"),
                    Host.os_info.like(f"%{search_term}%")
                )
            ).all()
    
    def get_hosts_by_filter(self, filters: Dict[str, Any]) -> List[Host]:
        """Get hosts by multiple filters"""
        with self.get_session() as session:
            query = session.query(Host)
            
            for key, value in filters.items():
                if hasattr(Host, key):
                    if key in ['os_info', 'hostname']:
                        query = query.filter(getattr(Host, key).like(f"%{value}%"))
                    else:
                        query = query.filter(getattr(Host, key) == value)
            
            return query.all()
    
    def get_host_statistics(self) -> Dict[str, Any]:
        """Get host statistics"""
        with self.get_session() as session:
            total_hosts = session.query(Host).count()
            active_hosts = session.query(Host).filter(Host.status == 'active').count()
            inactive_hosts = session.query(Host).filter(Host.status == 'inactive').count()
            error_hosts = session.query(Host).filter(Host.status == 'error').count()
            
            return {
                'total_hosts': total_hosts,
                'active_hosts': active_hosts,
                'inactive_hosts': inactive_hosts,
                'error_hosts': error_hosts,
            }
    
    # Scan history operations
    def create_scan_history(self, scan_data: Dict[str, Any]) -> ScanHistory:
        """Create a new scan history record"""
        with self.get_session() as session:
            scan = ScanHistory(**scan_data)
            session.add(scan)
            session.commit()
            session.refresh(scan)
            return scan
    
    def get_scan_history(self, host_id: Optional[int] = None, scan_type: Optional[str] = None, limit: int = 100) -> List[ScanHistory]:
        """Get scan history, optionally filtered by host ID and scan type"""
        with self.get_session() as session:
            query = session.query(ScanHistory)
            if host_id:
                query = query.filter(ScanHistory.host_id == host_id)
            if scan_type:
                query = query.filter(ScanHistory.scan_type == scan_type)
            return query.order_by(ScanHistory.timestamp.desc()).limit(limit).all()
    
    def delete_old_scan_history(self, days: int = 30) -> int:
        """Delete scan history older than specified days"""
        with self.get_session() as session:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            deleted_count = session.query(ScanHistory).filter(
                ScanHistory.timestamp < cutoff_date
            ).delete()
            session.commit()
            return deleted_count
    
    # Configuration operations
    def set_config(self, key: str, value: str) -> ConfigModel:
        """Set configuration value"""
        with self.get_session() as session:
            config = session.query(ConfigModel).filter(ConfigModel.key == key).first()
            if config:
                config.value = value
            else:
                config = ConfigModel(key=key, value=value)
                session.add(config)
            session.commit()
            session.refresh(config)
            return config
    
    def get_config(self, key: str) -> Optional[str]:
        """Get configuration value"""
        with self.get_session() as session:
            config = session.query(ConfigModel).filter(ConfigModel.key == key).first()
            return config.value if config else None
    
    def get_all_config(self) -> Dict[str, str]:
        """Get all configuration values"""
        with self.get_session() as session:
            configs = session.query(ConfigModel).all()
            return {config.key: config.value for config in configs}
    
    def delete_config(self, key: str) -> bool:
        """Delete configuration value"""
        with self.get_session() as session:
            config = session.query(ConfigModel).filter(ConfigModel.key == key).first()
            if config:
                session.delete(config)
                session.commit()
                return True
            return False
    
    # Database management
    def backup_database(self, backup_path: str) -> bool:
        """Backup database to file"""
        try:
            import shutil
            shutil.copy2(self.database_path, backup_path)
            return True
        except Exception as e:
            print(f"Error backing up database: {e}")
            return False
    
    def restore_database(self, backup_path: str) -> bool:
        """Restore database from file"""
        try:
            import shutil
            if os.path.exists(backup_path):
                shutil.copy2(backup_path, self.database_path)
                # Reinitialize database connection
                self.init_database()
                return True
            return False
        except Exception as e:
            print(f"Error restoring database: {e}")
            return False
    
    def vacuum_database(self) -> bool:
        """Vacuum database to reclaim space"""
        try:
            with self.get_session() as session:
                session.execute(text("VACUUM"))
                session.commit()
            return True
        except Exception as e:
            print(f"Error vacuuming database: {e}")
            return False
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get comprehensive database statistics"""
        with self.get_session() as session:
            total_hosts = session.query(Host).count()
            active_hosts = session.query(Host).filter(Host.status == 'active').count()
            inactive_hosts = session.query(Host).filter(Host.status == 'inactive').count()
            error_hosts = session.query(Host).filter(Host.status == 'error').count()
            total_scans = session.query(ScanHistory).count()
            
            # Get additional statistics
            recent_scans = session.query(ScanHistory).filter(
                ScanHistory.timestamp >= datetime.utcnow() - timedelta(days=7)
            ).count()
            
            return {
                'total_hosts': total_hosts,
                'active_hosts': active_hosts,
                'inactive_hosts': inactive_hosts,
                'error_hosts': error_hosts,
                'total_scans': total_scans,
                'recent_scans': recent_scans,
                'database_file': os.path.basename(self.database_path),
                'database_size': os.path.getsize(self.database_path) if os.path.exists(self.database_path) else 0
            }


# Global database manager instance
db_manager = DatabaseManager() 