"""
Logging utilities for NetScan

This module provides enhanced logging functionality with file rotation,
different log levels, and integration with the configuration system.
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime


class NetScanLogger:
    """Enhanced logger for NetScan with configuration integration"""
    
    def __init__(self, name: str = "netscan"):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)  # Set to DEBUG, handlers will filter
        self._configured = False
    
    def configure(self, 
                 level: str = "INFO",
                 file_enabled: bool = False,
                 file_path: str = "netscan.log",
                 max_size: int = 10485760,  # 10MB
                 backup_count: int = 5,
                 console_enabled: bool = True,
                 format_string: Optional[str] = None):
        """Configure the logger with specified settings"""
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Set log level
        log_level = getattr(logging, level.upper(), logging.INFO)
        
        # Default format
        if format_string is None:
            format_string = '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
        
        formatter = logging.Formatter(format_string)
        
        # Console handler
        if console_enabled:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(log_level)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
        
        # File handler with rotation
        if file_enabled:
            # Ensure log directory exists
            log_file_path = Path(file_path)
            log_file_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                filename=str(log_file_path),
                maxBytes=max_size,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(logging.DEBUG)  # File gets all messages
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        
        self._configured = True
        self.logger.info(f"Logger configured - Level: {level}, File: {file_enabled}")
    
    def configure_from_config_manager(self):
        """Configure logger from config manager settings"""
        try:
            from ..config import config_manager
            
            logging_config = config_manager.get_section('logging')
            
            self.configure(
                level=logging_config.get('level', 'INFO'),
                file_enabled=logging_config.get('file_enabled', False),
                file_path=logging_config.get('file_path', 'netscan.log'),
                max_size=logging_config.get('max_size', 10485760),
                backup_count=logging_config.get('backup_count', 5)
            )
        except Exception as e:
            # Fallback to default configuration
            self.configure()
            self.logger.warning(f"Could not load logging configuration: {e}")
    
    def get_logger(self) -> logging.Logger:
        """Get the configured logger instance"""
        if not self._configured:
            self.configure_from_config_manager()
        return self.logger


# Global logger instances
_main_logger = NetScanLogger("netscan")
_scanner_logger = NetScanLogger("netscan.scanner")
_database_logger = NetScanLogger("netscan.database")
_config_logger = NetScanLogger("netscan.config")
_reporting_logger = NetScanLogger("netscan.reporting")


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get a logger instance for the specified module"""
    if name is None:
        return _main_logger.get_logger()
    elif name.startswith("scanner"):
        return _scanner_logger.get_logger()
    elif name.startswith("database"):
        return _database_logger.get_logger()
    elif name.startswith("config"):
        return _config_logger.get_logger()
    elif name.startswith("reporting"):
        return _reporting_logger.get_logger()
    else:
        # Create a new logger for unknown modules
        logger = NetScanLogger(f"netscan.{name}")
        return logger.get_logger()


def setup_logging():
    """Setup logging for the entire application"""
    try:
        from ..config import config_manager
        
        logging_config = config_manager.get_section('logging')
        
        # Configure all loggers
        for logger_instance in [_main_logger, _scanner_logger, _database_logger, 
                              _config_logger, _reporting_logger]:
            logger_instance.configure(
                level=logging_config.get('level', 'INFO'),
                file_enabled=logging_config.get('file_enabled', False),
                file_path=logging_config.get('file_path', 'netscan.log'),
                max_size=logging_config.get('max_size', 10485760),
                backup_count=logging_config.get('backup_count', 5)
            )
    
    except Exception as e:
        # Fallback configuration
        _main_logger.configure()
        _main_logger.get_logger().warning(f"Could not setup logging from config: {e}")


def log_function_call(func):
    """Decorator to log function calls and execution time"""
    def wrapper(*args, **kwargs):
        logger = get_logger()
        func_name = f"{func.__module__}.{func.__name__}"
        
        start_time = datetime.now()
        logger.debug(f"Calling {func_name} with args={args}, kwargs={kwargs}")
        
        try:
            result = func(*args, **kwargs)
            execution_time = (datetime.now() - start_time).total_seconds()
            logger.debug(f"{func_name} completed in {execution_time:.3f}s")
            return result
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            logger.error(f"{func_name} failed after {execution_time:.3f}s: {e}")
            raise
    
    return wrapper


def log_exception(logger: logging.Logger, exception: Exception, context: str = ""):
    """Log an exception with full stack trace and context"""
    import traceback
    
    context_msg = f" ({context})" if context else ""
    logger.error(f"Exception occurred{context_msg}: {type(exception).__name__}: {exception}")
    logger.debug(f"Full traceback:\n{traceback.format_exc()}")


class LoggingContext:
    """Context manager for logging with automatic error handling"""
    
    def __init__(self, logger: logging.Logger, operation: str, log_start: bool = True):
        self.logger = logger
        self.operation = operation
        self.log_start = log_start
        self.start_time = None
    
    def __enter__(self):
        self.start_time = datetime.now()
        if self.log_start:
            self.logger.info(f"Starting {self.operation}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        execution_time = (datetime.now() - self.start_time).total_seconds()
        
        if exc_type is None:
            self.logger.info(f"Completed {self.operation} in {execution_time:.3f}s")
        else:
            self.logger.error(f"Failed {self.operation} after {execution_time:.3f}s: {exc_val}")
            log_exception(self.logger, exc_val, self.operation)
        
        return False  # Don't suppress exceptions


class NetworkOperationLogger:
    """Specialized logger for network operations"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def log_connection_attempt(self, host: str, port: int):
        """Log connection attempt"""
        self.logger.debug(f"Attempting connection to {host}:{port}")
    
    def log_connection_success(self, host: str, port: int, duration: float):
        """Log successful connection"""
        self.logger.info(f"Successfully connected to {host}:{port} in {duration:.3f}s")
    
    def log_connection_failure(self, host: str, port: int, error: str, duration: float):
        """Log connection failure"""
        self.logger.warning(f"Failed to connect to {host}:{port} after {duration:.3f}s: {error}")
    
    def log_timeout(self, host: str, port: int, timeout: int):
        """Log connection timeout"""
        self.logger.warning(f"Connection to {host}:{port} timed out after {timeout}s")
    
    def log_scan_progress(self, completed: int, total: int, current_host: str = None):
        """Log scan progress"""
        progress = (completed / total) * 100 if total > 0 else 0
        host_info = f" (current: {current_host})" if current_host else ""
        self.logger.info(f"Scan progress: {completed}/{total} ({progress:.1f}%){host_info}")


class DatabaseOperationLogger:
    """Specialized logger for database operations"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def log_query(self, operation: str, table: str, conditions: str = None):
        """Log database query"""
        cond_info = f" WHERE {conditions}" if conditions else ""
        self.logger.debug(f"Database {operation} on {table}{cond_info}")
    
    def log_transaction_start(self, operation: str):
        """Log transaction start"""
        self.logger.debug(f"Starting database transaction: {operation}")
    
    def log_transaction_commit(self, operation: str, duration: float):
        """Log transaction commit"""
        self.logger.debug(f"Committed database transaction: {operation} in {duration:.3f}s")
    
    def log_transaction_rollback(self, operation: str, error: str):
        """Log transaction rollback"""
        self.logger.warning(f"Rolled back database transaction: {operation} - {error}")
    
    def log_migration(self, version: str, direction: str):
        """Log database migration"""
        self.logger.info(f"Database migration {direction}: {version}")


class PerformanceLogger:
    """Logger for performance monitoring"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def log_memory_usage(self, operation: str, memory_mb: float):
        """Log memory usage"""
        self.logger.debug(f"Memory usage for {operation}: {memory_mb:.2f} MB")
    
    def log_execution_time(self, operation: str, duration: float, threshold: float = 1.0):
        """Log execution time with performance warning"""
        if duration > threshold:
            self.logger.warning(f"Slow operation detected: {operation} took {duration:.3f}s")
        else:
            self.logger.debug(f"Operation timing: {operation} took {duration:.3f}s")
    
    def log_resource_usage(self, cpu_percent: float, memory_mb: float, disk_io: dict = None):
        """Log system resource usage"""
        msg = f"Resource usage - CPU: {cpu_percent:.1f}%, Memory: {memory_mb:.2f} MB"
        if disk_io:
            msg += f", Disk I/O: {disk_io}"
        self.logger.debug(msg)


def get_network_logger() -> NetworkOperationLogger:
    """Get network operation logger"""
    return NetworkOperationLogger(get_logger("scanner.network"))


def get_database_logger() -> DatabaseOperationLogger:
    """Get database operation logger"""
    return DatabaseOperationLogger(get_logger("database"))


def get_performance_logger() -> PerformanceLogger:
    """Get performance logger"""
    return PerformanceLogger(get_logger("performance")) 