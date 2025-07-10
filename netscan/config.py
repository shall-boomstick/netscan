"""
Configuration management for NetScan

This module handles configuration loading, saving, and validation.
"""

import os
import json
import configparser
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime
import getpass

from .database.operations import db_manager
from .utils.logging import get_logger

logger = get_logger()


class ConfigManager:
    """Configuration manager for NetScan"""
    
    def __init__(self, config_dir: Optional[str] = None):
        self.config_dir = Path(config_dir) if config_dir else Path.home() / '.netscan'
        self.config_file = self.config_dir / 'config.conf'
        self.credentials_file = self.config_dir / 'credentials.json'
        self.config = {}
        self.defaults = {
            'scanning': {
                'default_port': 22,
                'default_timeout': 5,
                'default_threads': 10,
                'use_nmap': True,
                'max_retries': 3
            },
            'ssh': {
                'auth_timeout': 10,
                'key_discovery': True,
                'preferred_auth': 'key',  # 'key', 'password', 'agent'
                'connection_pool_size': 20
            },
            'database': {
                'path': 'netscan.db',
                'backup_enabled': True,
                'backup_interval': 7,  # days
                'vacuum_enabled': True
            },
            'reporting': {
                'default_format': 'table',
                'max_results': 1000,
                'export_timestamp': True,
                'include_metadata': True
            },
            'logging': {
                'level': 'INFO',
                'file_enabled': False,
                'file_path': 'netscan.log',
                'max_size': 10485760,  # 10MB
                'backup_count': 5
            }
        }
        
        # Ensure config directory exists
        self.config_dir.mkdir(exist_ok=True)
        self.load_config()
    
    def load_config(self):
        """Load configuration from file, environment variables, and database"""
        # Start with defaults
        self.config = self.defaults.copy()
        
        # Load from config file
        self._load_from_file()
        
        # Override with environment variables
        self._load_from_env()
        
        # Load from database
        self._load_from_database()
    
    def _load_from_file(self):
        """Load configuration from file"""
        if not self.config_file.exists():
            return
        
        try:
            config_parser = configparser.ConfigParser()
            config_parser.read(self.config_file)
            
            for section_name, section_config in self.config.items():
                if config_parser.has_section(section_name):
                    for key, default_value in section_config.items():
                        if config_parser.has_option(section_name, key):
                            value = config_parser.get(section_name, key)
                            
                            # Type conversion based on default value
                            if isinstance(default_value, bool):
                                self.config[section_name][key] = config_parser.getboolean(section_name, key)
                            elif isinstance(default_value, int):
                                self.config[section_name][key] = config_parser.getint(section_name, key)
                            elif isinstance(default_value, float):
                                self.config[section_name][key] = config_parser.getfloat(section_name, key)
                            else:
                                self.config[section_name][key] = value
            
            logger.info(f"Configuration loaded from {self.config_file}")
            
        except Exception as e:
            logger.error(f"Error loading configuration file: {e}")
    
    def _load_from_env(self):
        """Load configuration from environment variables"""
        env_mapping = {
            'NETSCAN_DEFAULT_PORT': ('scanning', 'default_port', int),
            'NETSCAN_DEFAULT_TIMEOUT': ('scanning', 'default_timeout', int),
            'NETSCAN_DEFAULT_THREADS': ('scanning', 'default_threads', int),
            'NETSCAN_USE_NMAP': ('scanning', 'use_nmap', bool),
            'NETSCAN_AUTH_TIMEOUT': ('ssh', 'auth_timeout', int),
            'NETSCAN_KEY_DISCOVERY': ('ssh', 'key_discovery', bool),
            'NETSCAN_PREFERRED_AUTH': ('ssh', 'preferred_auth', str),
            'NETSCAN_DB_PATH': ('database', 'path', str),
            'NETSCAN_LOG_LEVEL': ('logging', 'level', str),
            'NETSCAN_LOG_FILE': ('logging', 'file_path', str),
        }
        
        for env_var, (section, key, type_func) in env_mapping.items():
            value = os.getenv(env_var)
            if value is not None:
                try:
                    if type_func == bool:
                        self.config[section][key] = value.lower() in ('true', '1', 'yes', 'on')
                    else:
                        self.config[section][key] = type_func(value)
                    logger.debug(f"Environment variable {env_var} loaded")
                except ValueError as e:
                    logger.warning(f"Invalid value for {env_var}: {value} - {e}")
    
    def _load_from_database(self):
        """Load configuration from database"""
        try:
            db_config = db_manager.get_all_config()
            
            for key, value in db_config.items():
                # Parse key format: section.key
                if '.' in key:
                    section, config_key = key.split('.', 1)
                    if section in self.config and config_key in self.config[section]:
                        # Type conversion based on current value
                        current_value = self.config[section][config_key]
                        if isinstance(current_value, bool):
                            self.config[section][config_key] = value.lower() in ('true', '1', 'yes', 'on')
                        elif isinstance(current_value, int):
                            self.config[section][config_key] = int(value)
                        elif isinstance(current_value, float):
                            self.config[section][config_key] = float(value)
                        else:
                            self.config[section][config_key] = value
            
            logger.debug("Configuration loaded from database")
            
        except Exception as e:
            logger.warning(f"Error loading configuration from database: {e}")
    
    def save_config(self):
        """Save configuration to file"""
        try:
            config_parser = configparser.ConfigParser()
            
            for section_name, section_config in self.config.items():
                config_parser.add_section(section_name)
                for key, value in section_config.items():
                    config_parser.set(section_name, key, str(value))
            
            with open(self.config_file, 'w') as f:
                config_parser.write(f)
            
            logger.info(f"Configuration saved to {self.config_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False
    
    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        try:
            return self.config.get(section, {}).get(key, default)
        except Exception:
            return default
    
    def set(self, section: str, key: str, value: Any, save_to_db: bool = True):
        """Set configuration value"""
        if section not in self.config:
            self.config[section] = {}
        
        self.config[section][key] = value
        
        # Save to database
        if save_to_db:
            try:
                db_manager.set_config(f"{section}.{key}", str(value))
                logger.debug(f"Configuration {section}.{key} saved to database")
            except Exception as e:
                logger.error(f"Error saving configuration to database: {e}")
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire configuration section"""
        return self.config.get(section, {}).copy()
    
    def set_value(self, key: str, value: Any, save_to_db: bool = True):
        """Set configuration value using dot notation (section.key)"""
        if '.' in key:
            section, config_key = key.split('.', 1)
            self.set(section, config_key, value, save_to_db)
        else:
            logger.warning(f"Invalid configuration key format: {key}")
    
    def get_value(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation (section.key)"""
        if '.' in key:
            section, config_key = key.split('.', 1)
            return self.get(section, config_key, default)
        else:
            logger.warning(f"Invalid configuration key format: {key}")
            return default
    
    def validate_config(self) -> Dict[str, list]:
        """Validate configuration values"""
        errors = {}
        
        # Validate scanning configuration
        scanning = self.config.get('scanning', {})
        scanning_errors = []
        
        if not (1 <= scanning.get('default_port', 22) <= 65535):
            scanning_errors.append("default_port must be between 1 and 65535")
        
        if not (1 <= scanning.get('default_timeout', 5) <= 300):
            scanning_errors.append("default_timeout must be between 1 and 300 seconds")
        
        if not (1 <= scanning.get('default_threads', 10) <= 100):
            scanning_errors.append("default_threads must be between 1 and 100")
        
        if scanning_errors:
            errors['scanning'] = scanning_errors
        
        # Validate SSH configuration
        ssh = self.config.get('ssh', {})
        ssh_errors = []
        
        if not (1 <= ssh.get('auth_timeout', 10) <= 60):
            ssh_errors.append("auth_timeout must be between 1 and 60 seconds")
        
        if ssh.get('preferred_auth') not in ['key', 'password', 'agent']:
            ssh_errors.append("preferred_auth must be one of: key, password, agent")
        
        if ssh_errors:
            errors['ssh'] = ssh_errors
        
        # Validate logging configuration
        logging_config = self.config.get('logging', {})
        logging_errors = []
        
        if logging_config.get('level') not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            logging_errors.append("level must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL")
        
        if logging_errors:
            errors['logging'] = logging_errors
        
        return errors
    
    def get_credential(self, credential_type: str, default: str = None) -> Optional[str]:
        """Get stored credential"""
        try:
            if self.credentials_file.exists():
                with open(self.credentials_file, 'r') as f:
                    credentials = json.load(f)
                return credentials.get(credential_type, default)
        except Exception as e:
            logger.error(f"Error reading credentials: {e}")
        
        return default
    
    def set_credential(self, credential_type: str, value: str, encrypt: bool = True):
        """Set stored credential"""
        try:
            credentials = {}
            if self.credentials_file.exists():
                with open(self.credentials_file, 'r') as f:
                    credentials = json.load(f)
            
            # Simple encoding (not secure, but better than plain text)
            if encrypt:
                import base64
                value = base64.b64encode(value.encode()).decode()
            
            credentials[credential_type] = {
                'value': value,
                'encrypted': encrypt,
                'updated': datetime.now().isoformat()
            }
            
            with open(self.credentials_file, 'w') as f:
                json.dump(credentials, f, indent=2)
            
            # Set secure file permissions
            os.chmod(self.credentials_file, 0o600)
            
            logger.info(f"Credential {credential_type} stored")
            return True
            
        except Exception as e:
            logger.error(f"Error storing credential: {e}")
            return False
    
    def delete_credential(self, credential_type: str):
        """Delete stored credential"""
        try:
            if self.credentials_file.exists():
                with open(self.credentials_file, 'r') as f:
                    credentials = json.load(f)
                
                if credential_type in credentials:
                    del credentials[credential_type]
                    
                    with open(self.credentials_file, 'w') as f:
                        json.dump(credentials, f, indent=2)
                    
                    logger.info(f"Credential {credential_type} deleted")
                    return True
        except Exception as e:
            logger.error(f"Error deleting credential: {e}")
        
        return False
    
    def list_credentials(self) -> Dict[str, Dict[str, Any]]:
        """List all stored credentials (without values)"""
        try:
            if self.credentials_file.exists():
                with open(self.credentials_file, 'r') as f:
                    credentials = json.load(f)
                
                # Return metadata only, not the actual values
                return {
                    key: {
                        'encrypted': cred.get('encrypted', False),
                        'updated': cred.get('updated', 'Unknown')
                    }
                    for key, cred in credentials.items()
                }
        except Exception as e:
            logger.error(f"Error listing credentials: {e}")
        
        return {}
    
    def get_credential_value(self, credential_type: str) -> Optional[str]:
        """Get decrypted credential value"""
        try:
            if self.credentials_file.exists():
                with open(self.credentials_file, 'r') as f:
                    credentials = json.load(f)
                
                if credential_type in credentials:
                    cred = credentials[credential_type]
                    value = cred['value']
                    
                    if cred.get('encrypted', False):
                        import base64
                        value = base64.b64decode(value.encode()).decode()
                    
                    return value
        except Exception as e:
            logger.error(f"Error getting credential value: {e}")
        
        return None
    
    def prompt_for_credential(self, credential_type: str, prompt_text: str = None) -> Optional[str]:
        """Prompt user for credential and store it"""
        if not prompt_text:
            prompt_text = f"Enter {credential_type}: "
        
        try:
            if credential_type == 'password':
                value = getpass.getpass(prompt_text)
            else:
                value = input(prompt_text).strip()
            
            if value:
                self.set_credential(credential_type, value)
                return value
        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
        except Exception as e:
            logger.error(f"Error prompting for credential: {e}")
        
        return None
    
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self.config = self.defaults.copy()
        
        # Clear database configuration
        try:
            db_config = db_manager.get_all_config()
            for key in db_config.keys():
                if '.' in key:  # Only delete netscan config keys
                    db_manager.delete_config(key)
        except Exception as e:
            logger.error(f"Error clearing database configuration: {e}")
        
        logger.info("Configuration reset to defaults")
    
    def export_config(self, filepath: str) -> bool:
        """Export configuration to file"""
        try:
            export_data = {
                'config': self.config,
                'metadata': {
                    'export_time': datetime.now().isoformat(),
                    'version': '0.1.0',
                    'source': 'netscan'
                }
            }
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            logger.info(f"Configuration exported to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting configuration: {e}")
            return False
    
    def import_config(self, filepath: str) -> bool:
        """Import configuration from file"""
        try:
            with open(filepath, 'r') as f:
                import_data = json.load(f)
            
            if 'config' in import_data:
                self.config = import_data['config']
                self.save_config()
                logger.info(f"Configuration imported from {filepath}")
                return True
            else:
                logger.error("Invalid configuration file format")
                return False
                
        except Exception as e:
            logger.error(f"Error importing configuration: {e}")
            return False


# Global configuration manager instance
config_manager = ConfigManager() 