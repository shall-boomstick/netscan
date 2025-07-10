"""
Error handling utilities for NetScan

This module provides custom exceptions, retry mechanisms, graceful failure modes,
and comprehensive error handling utilities.
"""

import time
import socket
import functools
from typing import Callable, Any, Optional, Union, List, Type
from datetime import datetime, timedelta
import paramiko
import sqlite3
import logging

logger = logging.getLogger("netscan.error_handling")


# Custom Exception Classes
class NetScanError(Exception):
    """Base exception class for NetScan"""
    
    def __init__(self, message: str, details: dict = None, recoverable: bool = True):
        self.message = message
        self.details = details or {}
        self.recoverable = recoverable
        self.timestamp = datetime.now()
        super().__init__(self.message)
    
    def __str__(self):
        return f"{self.__class__.__name__}: {self.message}"
    
    def to_dict(self):
        """Convert exception to dictionary for logging/serialization"""
        return {
            'type': self.__class__.__name__,
            'message': self.message,
            'details': self.details,
            'recoverable': self.recoverable,
            'timestamp': self.timestamp.isoformat()
        }


class NetworkError(NetScanError):
    """Network-related errors"""
    pass


class SSHError(NetScanError):
    """SSH-related errors"""
    pass


class DatabaseError(NetScanError):
    """Database-related errors"""
    pass


class ConfigurationError(NetScanError):
    """Configuration-related errors"""
    
    def __init__(self, message: str, section: str = None, key: str = None, **kwargs):
        self.section = section
        self.key = key
        details = kwargs.get('details', {})
        if section:
            details['section'] = section
        if key:
            details['key'] = key
        super().__init__(message, details, **kwargs)


class ValidationError(NetScanError):
    """Input validation errors"""
    
    def __init__(self, message: str, field: str = None, value: Any = None, **kwargs):
        self.field = field
        self.value = value
        details = kwargs.get('details', {})
        if field:
            details['field'] = field
        if value is not None:
            details['value'] = str(value)
        super().__init__(message, details, **kwargs)


class AuthenticationError(SSHError):
    """SSH authentication errors"""
    
    def __init__(self, message: str, host: str = None, username: str = None, **kwargs):
        self.host = host
        self.username = username
        details = kwargs.get('details', {})
        if host:
            details['host'] = host
        if username:
            details['username'] = username
        super().__init__(message, details, **kwargs)


class ConnectionTimeoutError(NetworkError):
    """Connection timeout errors"""
    
    def __init__(self, message: str, host: str = None, port: int = None, timeout: int = None, **kwargs):
        self.host = host
        self.port = port
        self.timeout = timeout
        details = kwargs.get('details', {})
        if host:
            details['host'] = host
        if port:
            details['port'] = port
        if timeout:
            details['timeout'] = timeout
        super().__init__(message, details, **kwargs)


class HostUnreachableError(NetworkError):
    """Host unreachable errors"""
    
    def __init__(self, message: str, host: str = None, **kwargs):
        self.host = host
        details = kwargs.get('details', {})
        if host:
            details['host'] = host
        super().__init__(message, details, **kwargs)


class ResourceExhaustionError(NetScanError):
    """Resource exhaustion errors (memory, disk, connections, etc.)"""
    
    def __init__(self, message: str, resource_type: str = None, current_usage: Any = None, **kwargs):
        self.resource_type = resource_type
        self.current_usage = current_usage
        details = kwargs.get('details', {})
        if resource_type:
            details['resource_type'] = resource_type
        if current_usage is not None:
            details['current_usage'] = str(current_usage)
        super().__init__(message, details, **kwargs)


# Retry Mechanism
class RetryConfig:
    """Configuration for retry operations"""
    
    def __init__(self, 
                 max_attempts: int = 3,
                 base_delay: float = 1.0,
                 max_delay: float = 60.0,
                 exponential_backoff: bool = True,
                 jitter: bool = True,
                 retriable_exceptions: List[Type[Exception]] = None):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_backoff = exponential_backoff
        self.jitter = jitter
        self.retriable_exceptions = retriable_exceptions or [
            socket.timeout,
            socket.gaierror,
            ConnectionError,
            ConnectionTimeoutError,
            HostUnreachableError,
            paramiko.ssh_exception.NoValidConnectionsError,
            paramiko.ssh_exception.SSHException,
            sqlite3.OperationalError
        ]


def retry_operation(config: RetryConfig = None):
    """Decorator for retrying operations with configurable backoff"""
    
    if config is None:
        config = RetryConfig()
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(config.max_attempts):
                try:
                    return func(*args, **kwargs)
                
                except Exception as e:
                    last_exception = e
                    
                    # Check if this exception type is retriable
                    if not any(isinstance(e, exc_type) for exc_type in config.retriable_exceptions):
                        logger.error(f"Non-retriable exception in {func.__name__}: {e}")
                        raise
                    
                    # Don't retry on the last attempt
                    if attempt == config.max_attempts - 1:
                        break
                    
                    # Calculate delay
                    delay = config.base_delay
                    if config.exponential_backoff:
                        delay *= (2 ** attempt)
                    
                    # Apply jitter
                    if config.jitter:
                        import random
                        delay *= (0.5 + random.random() * 0.5)
                    
                    # Respect max delay
                    delay = min(delay, config.max_delay)
                    
                    logger.warning(f"Attempt {attempt + 1}/{config.max_attempts} failed for {func.__name__}: {e}. Retrying in {delay:.2f}s")
                    time.sleep(delay)
            
            # All attempts failed
            logger.error(f"All {config.max_attempts} attempts failed for {func.__name__}")
            if last_exception:
                raise last_exception
            else:
                raise NetScanError(f"Function {func.__name__} failed after {config.max_attempts} attempts")
        
        return wrapper
    return decorator


# Error Classification and Recovery
class ErrorRecoveryManager:
    """Manages error recovery strategies"""
    
    def __init__(self):
        self.recovery_strategies = {
            ConnectionTimeoutError: self._recover_connection_timeout,
            AuthenticationError: self._recover_authentication,
            DatabaseError: self._recover_database,
            ResourceExhaustionError: self._recover_resource_exhaustion,
            NetworkError: self._recover_network,
            SSHError: self._recover_ssh
        }
    
    def handle_error(self, error: Exception, context: dict = None) -> dict:
        """Handle an error and attempt recovery"""
        context = context or {}
        
        recovery_result = {
            'error': error,
            'context': context,
            'recovery_attempted': False,
            'recovery_successful': False,
            'recovery_strategy': None,
            'recommendations': []
        }
        
        # Log the error
        log_exception(logger, error, f"Error in {context.get('operation', 'unknown operation')}")
        
        # Find appropriate recovery strategy
        for error_type, strategy in self.recovery_strategies.items():
            if isinstance(error, error_type):
                try:
                    recovery_result['recovery_attempted'] = True
                    recovery_result['recovery_strategy'] = strategy.__name__
                    
                    strategy_result = strategy(error, context)
                    recovery_result.update(strategy_result)
                    
                    if recovery_result['recovery_successful']:
                        logger.info(f"Successfully recovered from {type(error).__name__}")
                    else:
                        logger.warning(f"Failed to recover from {type(error).__name__}")
                    
                    break
                
                except Exception as recovery_error:
                    logger.error(f"Recovery strategy failed: {recovery_error}")
                    recovery_result['recovery_error'] = str(recovery_error)
        
        return recovery_result
    
    def _recover_connection_timeout(self, error: ConnectionTimeoutError, context: dict) -> dict:
        """Recover from connection timeout"""
        recommendations = []
        
        if hasattr(error, 'timeout') and error.timeout:
            if error.timeout < 10:
                recommendations.append("Consider increasing timeout value")
            if error.timeout > 60:
                recommendations.append("Timeout is very high, check network connectivity")
        
        if hasattr(error, 'host'):
            recommendations.append(f"Verify host {error.host} is reachable")
        
        recommendations.extend([
            "Check network connectivity",
            "Verify firewall settings",
            "Consider using different network interface"
        ])
        
        return {
            'recovery_successful': False,
            'recommendations': recommendations
        }
    
    def _recover_authentication(self, error: AuthenticationError, context: dict) -> dict:
        """Recover from authentication error"""
        recommendations = []
        
        if hasattr(error, 'username'):
            recommendations.append(f"Verify username '{error.username}' is correct")
        
        recommendations.extend([
            "Check password/key file",
            "Verify SSH key permissions (600)",
            "Try different authentication method",
            "Check if account is locked",
            "Verify SSH service is running on target"
        ])
        
        return {
            'recovery_successful': False,
            'recommendations': recommendations
        }
    
    def _recover_database(self, error: DatabaseError, context: dict) -> dict:
        """Recover from database error"""
        recommendations = []
        recovery_successful = False
        
        # Try to recreate database connection
        try:
            from ..database.operations import db_manager
            db_manager.init_database()
            recovery_successful = True
            logger.info("Successfully reconnected to database")
        except Exception as e:
            logger.error(f"Failed to reconnect to database: {e}")
            recommendations.append("Database connection failed - manual intervention required")
        
        recommendations.extend([
            "Check database file permissions",
            "Verify disk space availability",
            "Consider database backup/restore",
            "Check for database corruption"
        ])
        
        return {
            'recovery_successful': recovery_successful,
            'recommendations': recommendations
        }
    
    def _recover_resource_exhaustion(self, error: ResourceExhaustionError, context: dict) -> dict:
        """Recover from resource exhaustion"""
        recommendations = []
        
        if hasattr(error, 'resource_type'):
            if error.resource_type == 'memory':
                recommendations.extend([
                    "Reduce number of concurrent threads",
                    "Process data in smaller batches",
                    "Clear unused objects from memory"
                ])
            elif error.resource_type == 'disk':
                recommendations.extend([
                    "Clean up temporary files",
                    "Rotate log files",
                    "Move data to different disk"
                ])
            elif error.resource_type == 'connections':
                recommendations.extend([
                    "Reduce connection pool size",
                    "Implement connection reuse",
                    "Add connection timeout"
                ])
        
        recommendations.append("Monitor system resources")
        
        return {
            'recovery_successful': False,
            'recommendations': recommendations
        }
    
    def _recover_network(self, error: NetworkError, context: dict) -> dict:
        """Recover from network error"""
        recommendations = [
            "Check network connectivity",
            "Verify DNS resolution",
            "Test with different network interface",
            "Check routing table",
            "Verify target host is up"
        ]
        
        return {
            'recovery_successful': False,
            'recommendations': recommendations
        }
    
    def _recover_ssh(self, error: SSHError, context: dict) -> dict:
        """Recover from SSH error"""
        recommendations = [
            "Verify SSH service is running",
            "Check SSH configuration",
            "Verify user permissions",
            "Test SSH connection manually",
            "Check SSH logs on target system"
        ]
        
        return {
            'recovery_successful': False,
            'recommendations': recommendations
        }


# Global error recovery manager
error_recovery_manager = ErrorRecoveryManager()


# Context Managers for Error Handling
class GracefulErrorHandler:
    """Context manager for graceful error handling"""
    
    def __init__(self, 
                 operation_name: str,
                 logger_instance: Any = None,
                 reraise: bool = True,
                 default_return: Any = None,
                 recovery_manager: ErrorRecoveryManager = None):
        self.operation_name = operation_name
        self.logger_instance = logger_instance or logger
        self.reraise = reraise
        self.default_return = default_return
        self.recovery_manager = recovery_manager or error_recovery_manager
        self.start_time = None
    
    def __enter__(self):
        self.start_time = datetime.now()
        self.logger_instance.debug(f"Starting operation: {self.operation_name}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (datetime.now() - self.start_time).total_seconds()
        
        if exc_type is None:
            self.logger_instance.info(f"Operation completed successfully: {self.operation_name} ({duration:.3f}s)")
            return False
        
        # Handle the error
        context = {
            'operation': self.operation_name,
            'duration': duration
        }
        
        recovery_result = self.recovery_manager.handle_error(exc_val, context)
        
        if not self.reraise:
            self.logger_instance.warning(f"Suppressing error in {self.operation_name}: {exc_val}")
            return True  # Suppress the exception
        
        return False  # Re-raise the exception


# Utility Functions
def safe_execute(func: Callable, *args, default_return: Any = None, log_errors: bool = True, **kwargs) -> Any:
    """Safely execute a function with error handling"""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        if log_errors:
            log_exception(logger, e, f"safe_execute({func.__name__})")
        return default_return


def validate_input(value: Any, 
                  validators: List[Callable] = None,
                  field_name: str = "input",
                  required: bool = True) -> Any:
    """Validate input with custom validators"""
    
    if value is None and required:
        raise ValidationError(f"{field_name} is required", field=field_name, value=value)
    
    if value is None:
        return value
    
    if validators:
        for validator in validators:
            try:
                if not validator(value):
                    raise ValidationError(f"{field_name} failed validation", field=field_name, value=value)
            except Exception as e:
                raise ValidationError(f"Validation error for {field_name}: {e}", field=field_name, value=value)
    
    return value


def create_timeout_context(timeout_seconds: int, operation_name: str = "operation"):
    """Create a timeout context manager"""
    import signal
    
    class TimeoutContext:
        def __init__(self, timeout: int, name: str):
            self.timeout = timeout
            self.name = name
            self.old_handler = None
        
        def timeout_handler(self, signum, frame):
            raise ConnectionTimeoutError(
                f"Operation '{self.name}' timed out after {self.timeout} seconds",
                timeout=self.timeout
            )
        
        def __enter__(self):
            self.old_handler = signal.signal(signal.SIGALRM, self.timeout_handler)
            signal.alarm(self.timeout)
            return self
        
        def __exit__(self, exc_type, exc_val, exc_tb):
            signal.alarm(0)
            if self.old_handler:
                signal.signal(signal.SIGALRM, self.old_handler)
    
    return TimeoutContext(timeout_seconds, operation_name)


def handle_keyboard_interrupt(func: Callable) -> Callable:
    """Decorator to handle keyboard interrupts gracefully"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            logger.info(f"Operation {func.__name__} interrupted by user")
            raise NetScanError("Operation interrupted by user", recoverable=False)
    
    return wrapper


# Exception mapping for common errors
def log_exception(logger_instance: logging.Logger, exception: Exception, context: str = ""):
    """Log an exception with full stack trace and context"""
    import traceback
    
    context_msg = f" ({context})" if context else ""
    logger_instance.error(f"Exception occurred{context_msg}: {type(exception).__name__}: {exception}")
    logger_instance.debug(f"Full traceback:\n{traceback.format_exc()}")


def map_exception(exception: Exception) -> NetScanError:
    """Map common exceptions to NetScan custom exceptions"""
    
    if isinstance(exception, socket.timeout):
        return ConnectionTimeoutError("Connection timed out", details={'original_error': str(exception)})
    
    elif isinstance(exception, socket.gaierror):
        return HostUnreachableError("Host name resolution failed", details={'original_error': str(exception)})
    
    elif isinstance(exception, ConnectionRefusedError):
        return NetworkError("Connection refused", details={'original_error': str(exception)})
    
    elif isinstance(exception, paramiko.AuthenticationException):
        return AuthenticationError("SSH authentication failed", details={'original_error': str(exception)})
    
    elif isinstance(exception, paramiko.ssh_exception.NoValidConnectionsError):
        return NetworkError("No valid SSH connections available", details={'original_error': str(exception)})
    
    elif isinstance(exception, sqlite3.Error):
        return DatabaseError("Database operation failed", details={'original_error': str(exception)})
    
    elif isinstance(exception, FileNotFoundError):
        return ConfigurationError("Required file not found", details={'original_error': str(exception)})
    
    elif isinstance(exception, PermissionError):
        return ConfigurationError("Permission denied", details={'original_error': str(exception)})
    
    else:
        # Wrap unknown exceptions
        return NetScanError(f"Unexpected error: {exception}", details={'original_error': str(exception)}) 