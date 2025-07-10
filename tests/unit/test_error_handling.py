"""
Unit tests for error handling utilities
"""

import pytest
import socket
import time
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from netscan.utils.error_handling import (
    NetScanError, NetworkError, SSHError, DatabaseError, ConfigurationError,
    ValidationError, AuthenticationError, ConnectionTimeoutError, 
    HostUnreachableError, ResourceExhaustionError, RetryConfig, 
    retry_operation, ErrorRecoveryManager, GracefulErrorHandler,
    safe_execute, validate_input, map_exception, log_exception
)


class TestNetScanExceptions:
    """Test cases for custom exception classes"""
    
    def test_netscan_error_base(self):
        """Test base NetScanError exception"""
        error = NetScanError("Test error", details={'key': 'value'}, recoverable=False)
        
        assert str(error) == "NetScanError: Test error"
        assert error.message == "Test error"
        assert error.details == {'key': 'value'}
        assert error.recoverable is False
        assert isinstance(error.timestamp, datetime)
    
    def test_netscan_error_to_dict(self):
        """Test NetScanError to_dict method"""
        error = NetScanError("Test error", details={'key': 'value'})
        error_dict = error.to_dict()
        
        assert error_dict['type'] == 'NetScanError'
        assert error_dict['message'] == "Test error"
        assert error_dict['details'] == {'key': 'value'}
        assert error_dict['recoverable'] is True
        assert 'timestamp' in error_dict
    
    def test_network_error(self):
        """Test NetworkError exception"""
        error = NetworkError("Network connection failed")
        
        assert isinstance(error, NetScanError)
        assert str(error) == "NetworkError: Network connection failed"
    
    def test_ssh_error(self):
        """Test SSHError exception"""
        error = SSHError("SSH connection failed")
        
        assert isinstance(error, NetScanError)
        assert str(error) == "SSHError: SSH connection failed"
    
    def test_database_error(self):
        """Test DatabaseError exception"""
        error = DatabaseError("Database operation failed")
        
        assert isinstance(error, NetScanError)
        assert str(error) == "DatabaseError: Database operation failed"
    
    def test_configuration_error(self):
        """Test ConfigurationError exception"""
        error = ConfigurationError("Invalid configuration", section="scanning", key="timeout")
        
        assert isinstance(error, NetScanError)
        assert error.section == "scanning"
        assert error.key == "timeout"
        assert error.details['section'] == "scanning"
        assert error.details['key'] == "timeout"
    
    def test_validation_error(self):
        """Test ValidationError exception"""
        error = ValidationError("Invalid input", field="ip_address", value="invalid-ip")
        
        assert isinstance(error, NetScanError)
        assert error.field == "ip_address"
        assert error.value == "invalid-ip"
        assert error.details['field'] == "ip_address"
        assert error.details['value'] == "invalid-ip"
    
    def test_authentication_error(self):
        """Test AuthenticationError exception"""
        error = AuthenticationError("Auth failed", host="192.168.1.100", username="admin")
        
        assert isinstance(error, SSHError)
        assert error.host == "192.168.1.100"
        assert error.username == "admin"
        assert error.details['host'] == "192.168.1.100"
        assert error.details['username'] == "admin"
    
    def test_connection_timeout_error(self):
        """Test ConnectionTimeoutError exception"""
        error = ConnectionTimeoutError("Timeout", host="192.168.1.100", port=22, timeout=5)
        
        assert isinstance(error, NetworkError)
        assert error.host == "192.168.1.100"
        assert error.port == 22
        assert error.timeout == 5
        assert error.details['host'] == "192.168.1.100"
        assert error.details['port'] == 22
        assert error.details['timeout'] == 5
    
    def test_host_unreachable_error(self):
        """Test HostUnreachableError exception"""
        error = HostUnreachableError("Host unreachable", host="192.168.1.100")
        
        assert isinstance(error, NetworkError)
        assert error.host == "192.168.1.100"
        assert error.details['host'] == "192.168.1.100"
    
    def test_resource_exhaustion_error(self):
        """Test ResourceExhaustionError exception"""
        error = ResourceExhaustionError("Out of memory", resource_type="memory", current_usage="8GB")
        
        assert isinstance(error, NetScanError)
        assert error.resource_type == "memory"
        assert error.current_usage == "8GB"
        assert error.details['resource_type'] == "memory"
        assert error.details['current_usage'] == "8GB"


class TestRetryMechanism:
    """Test cases for retry mechanism"""
    
    def test_retry_config_defaults(self):
        """Test RetryConfig with default values"""
        config = RetryConfig()
        
        assert config.max_attempts == 3
        assert config.base_delay == 1.0
        assert config.max_delay == 60.0
        assert config.exponential_backoff is True
        assert config.jitter is True
        assert len(config.retriable_exceptions) > 0
    
    def test_retry_config_custom(self):
        """Test RetryConfig with custom values"""
        custom_exceptions = [ValueError, TypeError]
        config = RetryConfig(
            max_attempts=5,
            base_delay=0.5,
            max_delay=30.0,
            exponential_backoff=False,
            jitter=False,
            retriable_exceptions=custom_exceptions
        )
        
        assert config.max_attempts == 5
        assert config.base_delay == 0.5
        assert config.max_delay == 30.0
        assert config.exponential_backoff is False
        assert config.jitter is False
        assert config.retriable_exceptions == custom_exceptions
    
    def test_retry_operation_success_first_attempt(self):
        """Test retry decorator with successful first attempt"""
        call_count = 0
        
        @retry_operation(RetryConfig(max_attempts=3))
        def test_function():
            nonlocal call_count
            call_count += 1
            return "success"
        
        result = test_function()
        
        assert result == "success"
        assert call_count == 1
    
    def test_retry_operation_success_after_retries(self):
        """Test retry decorator with success after retries"""
        call_count = 0
        
        @retry_operation(RetryConfig(max_attempts=3, base_delay=0.1))
        def test_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise socket.timeout("Timeout")
            return "success"
        
        result = test_function()
        
        assert result == "success"
        assert call_count == 3
    
    def test_retry_operation_all_attempts_fail(self):
        """Test retry decorator when all attempts fail"""
        call_count = 0
        
        @retry_operation(RetryConfig(max_attempts=3, base_delay=0.1))
        def test_function():
            nonlocal call_count
            call_count += 1
            raise socket.timeout("Timeout")
        
        with pytest.raises(socket.timeout):
            test_function()
        
        assert call_count == 3
    
    def test_retry_operation_non_retriable_exception(self):
        """Test retry decorator with non-retriable exception"""
        call_count = 0
        
        @retry_operation(RetryConfig(max_attempts=3, retriable_exceptions=[socket.timeout]))
        def test_function():
            nonlocal call_count
            call_count += 1
            raise ValueError("Non-retriable error")
        
        with pytest.raises(ValueError):
            test_function()
        
        assert call_count == 1  # Should not retry
    
    @patch('time.sleep')
    def test_retry_operation_delay_calculation(self, mock_sleep):
        """Test retry delay calculation"""
        call_count = 0
        
        @retry_operation(RetryConfig(max_attempts=3, base_delay=1.0, exponential_backoff=True, jitter=False))
        def test_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise socket.timeout("Timeout")
            return "success"
        
        result = test_function()
        
        assert result == "success"
        assert call_count == 3
        assert mock_sleep.call_count == 2  # Two retries
        
        # Check exponential backoff: 1.0, 2.0
        expected_delays = [1.0, 2.0]
        actual_delays = [call.args[0] for call in mock_sleep.call_args_list]
        assert actual_delays == expected_delays


class TestErrorRecoveryManager:
    """Test cases for ErrorRecoveryManager"""
    
    def setup_method(self):
        """Setup test recovery manager"""
        self.recovery_manager = ErrorRecoveryManager()
    
    def test_handle_connection_timeout_error(self):
        """Test handling ConnectionTimeoutError"""
        error = ConnectionTimeoutError("Connection timeout", host="192.168.1.100", timeout=5)
        context = {'operation': 'ssh_connect'}
        
        result = self.recovery_manager.handle_error(error, context)
        
        assert result['error'] == error
        assert result['context'] == context
        assert result['recovery_attempted'] is True
        assert result['recovery_successful'] is False
        assert len(result['recommendations']) > 0
        assert any('timeout' in rec.lower() for rec in result['recommendations'])
    
    def test_handle_authentication_error(self):
        """Test handling AuthenticationError"""
        error = AuthenticationError("Auth failed", host="192.168.1.100", username="admin")
        context = {'operation': 'ssh_login'}
        
        result = self.recovery_manager.handle_error(error, context)
        
        assert result['recovery_attempted'] is True
        assert result['recovery_successful'] is False
        assert len(result['recommendations']) > 0
        assert any('password' in rec.lower() or 'key' in rec.lower() for rec in result['recommendations'])
    
    def test_handle_database_error(self):
        """Test handling DatabaseError"""
        error = DatabaseError("Database connection failed")
        context = {'operation': 'create_host'}
        
        result = self.recovery_manager.handle_error(error, context)
        
        assert result['recovery_attempted'] is True
        assert len(result['recommendations']) > 0
        assert any('database' in rec.lower() for rec in result['recommendations'])
    
    def test_handle_resource_exhaustion_error(self):
        """Test handling ResourceExhaustionError"""
        error = ResourceExhaustionError("Out of memory", resource_type="memory")
        context = {'operation': 'large_scan'}
        
        result = self.recovery_manager.handle_error(error, context)
        
        assert result['recovery_attempted'] is True
        assert result['recovery_successful'] is False
        assert len(result['recommendations']) > 0
        assert any('memory' in rec.lower() for rec in result['recommendations'])
    
    def test_handle_unknown_error(self):
        """Test handling unknown error type"""
        error = ValueError("Unknown error")
        context = {'operation': 'test'}
        
        result = self.recovery_manager.handle_error(error, context)
        
        assert result['recovery_attempted'] is False
        assert result['recovery_successful'] is False
        assert len(result['recommendations']) == 0
    
    def test_recovery_strategy_exception(self):
        """Test recovery strategy that throws exception"""
        # Mock a recovery strategy that fails
        original_strategy = self.recovery_manager._recover_network
        
        def failing_strategy(error, context):
            raise Exception("Recovery failed")
        
        self.recovery_manager._recover_network = failing_strategy
        
        error = NetworkError("Network failed")
        result = self.recovery_manager.handle_error(error)
        
        assert result['recovery_attempted'] is True
        assert 'recovery_error' in result
        assert "Recovery failed" in result['recovery_error']
        
        # Restore original strategy
        self.recovery_manager._recover_network = original_strategy


class TestGracefulErrorHandler:
    """Test cases for GracefulErrorHandler context manager"""
    
    def test_graceful_error_handler_success(self):
        """Test GracefulErrorHandler with successful operation"""
        logger = Mock()
        
        with GracefulErrorHandler("test_operation", logger):
            result = "success"
        
        assert result == "success"
        logger.debug.assert_called_once()
        logger.info.assert_called_once()
    
    def test_graceful_error_handler_with_exception_reraise(self):
        """Test GracefulErrorHandler with exception (reraise=True)"""
        logger = Mock()
        
        with pytest.raises(ValueError):
            with GracefulErrorHandler("test_operation", logger, reraise=True):
                raise ValueError("Test error")
        
        logger.debug.assert_called_once()
        logger.error.assert_called_once()
    
    def test_graceful_error_handler_with_exception_suppress(self):
        """Test GracefulErrorHandler with exception (reraise=False)"""
        logger = Mock()
        
        with GracefulErrorHandler("test_operation", logger, reraise=False):
            raise ValueError("Test error")
        
        logger.debug.assert_called_once()
        logger.warning.assert_called_once()
    
    def test_graceful_error_handler_with_recovery_manager(self):
        """Test GracefulErrorHandler with recovery manager"""
        logger = Mock()
        recovery_manager = Mock()
        recovery_manager.handle_error.return_value = {'recovery_attempted': True}
        
        with pytest.raises(ValueError):
            with GracefulErrorHandler("test_operation", logger, recovery_manager=recovery_manager):
                raise ValueError("Test error")
        
        recovery_manager.handle_error.assert_called_once()


class TestUtilityFunctions:
    """Test cases for utility functions"""
    
    def test_safe_execute_success(self):
        """Test safe_execute with successful function"""
        def test_function(x, y):
            return x + y
        
        result = safe_execute(test_function, 2, 3)
        
        assert result == 5
    
    def test_safe_execute_with_exception(self):
        """Test safe_execute with exception"""
        def test_function():
            raise ValueError("Test error")
        
        result = safe_execute(test_function, default_return="default")
        
        assert result == "default"
    
    def test_safe_execute_with_logging(self):
        """Test safe_execute with error logging"""
        def test_function():
            raise ValueError("Test error")
        
        result = safe_execute(test_function, default_return="default", log_errors=True)
        
        assert result == "default"
        # Logger should have been called (though we're not mocking it in this test)
    
    def test_validate_input_success(self):
        """Test validate_input with valid input"""
        def is_positive(x):
            return x > 0
        
        result = validate_input(5, validators=[is_positive], field_name="number")
        
        assert result == 5
    
    def test_validate_input_required_missing(self):
        """Test validate_input with required field missing"""
        with pytest.raises(ValidationError) as exc_info:
            validate_input(None, field_name="required_field", required=True)
        
        assert "required_field is required" in str(exc_info.value)
    
    def test_validate_input_validation_failure(self):
        """Test validate_input with validation failure"""
        def is_positive(x):
            return x > 0
        
        with pytest.raises(ValidationError) as exc_info:
            validate_input(-1, validators=[is_positive], field_name="number")
        
        assert "number failed validation" in str(exc_info.value)
    
    def test_validate_input_validator_exception(self):
        """Test validate_input with validator that raises exception"""
        def failing_validator(x):
            raise ValueError("Validator error")
        
        with pytest.raises(ValidationError) as exc_info:
            validate_input(5, validators=[failing_validator], field_name="number")
        
        assert "Validation error for number" in str(exc_info.value)
    
    def test_validate_input_optional_none(self):
        """Test validate_input with optional None value"""
        result = validate_input(None, field_name="optional_field", required=False)
        
        assert result is None
    
    def test_map_exception_socket_timeout(self):
        """Test mapping socket.timeout to ConnectionTimeoutError"""
        original_error = socket.timeout("Connection timed out")
        
        mapped_error = map_exception(original_error)
        
        assert isinstance(mapped_error, ConnectionTimeoutError)
        assert "Connection timed out" in mapped_error.message
    
    def test_map_exception_socket_gaierror(self):
        """Test mapping socket.gaierror to HostUnreachableError"""
        original_error = socket.gaierror("Name resolution failed")
        
        mapped_error = map_exception(original_error)
        
        assert isinstance(mapped_error, HostUnreachableError)
        assert "Host name resolution failed" in mapped_error.message
    
    def test_map_exception_connection_refused(self):
        """Test mapping ConnectionRefusedError to NetworkError"""
        original_error = ConnectionRefusedError("Connection refused")
        
        mapped_error = map_exception(original_error)
        
        assert isinstance(mapped_error, NetworkError)
        assert "Connection refused" in mapped_error.message
    
    def test_map_exception_file_not_found(self):
        """Test mapping FileNotFoundError to ConfigurationError"""
        original_error = FileNotFoundError("File not found")
        
        mapped_error = map_exception(original_error)
        
        assert isinstance(mapped_error, ConfigurationError)
        assert "Required file not found" in mapped_error.message
    
    def test_map_exception_unknown_error(self):
        """Test mapping unknown exception to NetScanError"""
        original_error = RuntimeError("Unknown error")
        
        mapped_error = map_exception(original_error)
        
        assert isinstance(mapped_error, NetScanError)
        assert "Unexpected error" in mapped_error.message
        assert "Unknown error" in mapped_error.message
    
    def test_log_exception(self):
        """Test log_exception function"""
        logger = Mock()
        error = ValueError("Test error")
        
        log_exception(logger, error, "test context")
        
        logger.error.assert_called_once()
        logger.debug.assert_called_once()
        
        # Check that the error message contains context
        error_call = logger.error.call_args[0][0]
        assert "test context" in error_call
        assert "ValueError" in error_call
        assert "Test error" in error_call


class TestTimeoutContext:
    """Test cases for timeout context manager"""
    
    @patch('signal.signal')
    @patch('signal.alarm')
    def test_timeout_context_success(self, mock_alarm, mock_signal):
        """Test timeout context with successful operation"""
        from netscan.utils.error_handling import create_timeout_context
        
        with create_timeout_context(5, "test_operation"):
            result = "success"
        
        assert result == "success"
        mock_alarm.assert_any_call(5)
        mock_alarm.assert_any_call(0)  # Reset alarm
    
    @patch('signal.signal')
    @patch('signal.alarm')
    def test_timeout_context_with_exception(self, mock_alarm, mock_signal):
        """Test timeout context with exception"""
        from netscan.utils.error_handling import create_timeout_context
        
        with pytest.raises(ValueError):
            with create_timeout_context(5, "test_operation"):
                raise ValueError("Test error")
        
        mock_alarm.assert_any_call(5)
        mock_alarm.assert_any_call(0)  # Reset alarm even after exception


class TestKeyboardInterruptHandler:
    """Test cases for keyboard interrupt handler"""
    
    def test_keyboard_interrupt_handler_success(self):
        """Test keyboard interrupt handler with successful function"""
        from netscan.utils.error_handling import handle_keyboard_interrupt
        
        @handle_keyboard_interrupt
        def test_function():
            return "success"
        
        result = test_function()
        
        assert result == "success"
    
    def test_keyboard_interrupt_handler_with_interrupt(self):
        """Test keyboard interrupt handler with KeyboardInterrupt"""
        from netscan.utils.error_handling import handle_keyboard_interrupt
        
        @handle_keyboard_interrupt
        def test_function():
            raise KeyboardInterrupt()
        
        with pytest.raises(NetScanError) as exc_info:
            test_function()
        
        assert "Operation interrupted by user" in str(exc_info.value)
        assert exc_info.value.recoverable is False
    
    def test_keyboard_interrupt_handler_with_other_exception(self):
        """Test keyboard interrupt handler with other exception"""
        from netscan.utils.error_handling import handle_keyboard_interrupt
        
        @handle_keyboard_interrupt
        def test_function():
            raise ValueError("Other error")
        
        with pytest.raises(ValueError):
            test_function()


class TestPerformanceAndStress:
    """Performance and stress tests for error handling"""
    
    def test_retry_mechanism_performance(self):
        """Test retry mechanism performance with many operations"""
        call_count = 0
        
        @retry_operation(RetryConfig(max_attempts=2, base_delay=0.01))
        def fast_function():
            nonlocal call_count
            call_count += 1
            return "success"
        
        # Run many operations
        start_time = time.time()
        for _ in range(100):
            result = fast_function()
            assert result == "success"
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should complete quickly (less than 1 second for 100 operations)
        assert duration < 1.0
        assert call_count == 100
    
    def test_error_recovery_manager_performance(self):
        """Test error recovery manager performance"""
        recovery_manager = ErrorRecoveryManager()
        
        # Create many different errors
        errors = [
            ConnectionTimeoutError("Timeout"),
            AuthenticationError("Auth failed"),
            DatabaseError("DB error"),
            NetworkError("Network error"),
            ResourceExhaustionError("Out of memory")
        ]
        
        start_time = time.time()
        for _ in range(50):
            for error in errors:
                result = recovery_manager.handle_error(error)
                assert result['recovery_attempted'] is True
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should handle 250 errors quickly (less than 1 second)
        assert duration < 1.0
    
    def test_exception_creation_overhead(self):
        """Test overhead of creating custom exceptions"""
        start_time = time.time()
        
        # Create many exceptions
        for i in range(1000):
            error = NetworkError(f"Error {i}", details={'index': i})
            assert error.message == f"Error {i}"
            assert error.details['index'] == i
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should create exceptions quickly (less than 0.1 second for 1000)
        assert duration < 0.1 