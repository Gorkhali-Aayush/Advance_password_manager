"""
Configuration Management

Load configuration from environment variables or config file.
Centralizes all configuration in one place.
"""

import os
from typing import Any, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class Config:
    """Application configuration manager."""
    
    # Default configuration values
    DEFAULTS = {
        'DB_HOST': 'localhost',
        'DB_PORT': 3306,
        'DB_USER': 'root',
        'DB_PASSWORD': 'root',
        'DB_NAME': 'password_manager',
        'AUTO_LOCK_TIMEOUT': 300,
        'CLIPBOARD_CLEAR_TIMEOUT': 30,
        'PBKDF2_ITERATIONS': 100000,
        'LOG_LEVEL': 'INFO',
        'ENABLE_ADMIN_DASHBOARD': True,
        'ENABLE_GRAPH_VISUALIZATION': True,
        'ENABLE_PASSWORD_HISTORY': True,
        'ENABLE_BACKUP_RESTORE': True,
    }
    
    def __init__(self):
        """Initialize configuration from environment."""
        self._config = self.DEFAULTS.copy()
        self._load_env()
    
    def _load_env(self) -> None:
        """Load configuration from environment variables."""
        env_file = Path('.env')
        if env_file.exists():
            self._load_env_file(env_file)
        
        # Override with actual environment variables
        for key in self.DEFAULTS:
            env_val = os.getenv(key)
            if env_val is not None:
                self._config[key] = self._parse_value(key, env_val)
    
    def _load_env_file(self, file_path: Path) -> None:
        """Load configuration from .env file."""
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        if key in self.DEFAULTS:
                            self._config[key] = self._parse_value(key, value)
        except Exception as e:
            logger.warning(f"Failed to load .env file: {e}")
    
    def _parse_value(self, key: str, value: str) -> Any:
        """Parse string value to appropriate type."""
        # Integer values
        if key in ('DB_PORT', 'AUTO_LOCK_TIMEOUT', 'CLIPBOARD_CLEAR_TIMEOUT', 'PBKDF2_ITERATIONS'):
            try:
                return int(value)
            except ValueError:
                return self.DEFAULTS[key]
        
        # Boolean values
        if key.startswith('ENABLE_'):
            return value.lower() in ('true', '1', 'yes', 'on')
        
        # String values
        return value
    
    def get(self, key: str, default: Optional[Any] = None) -> Any:
        """Get configuration value."""
        return self._config.get(key, default or self.DEFAULTS.get(key))
    
    def get_db_config(self) -> dict:
        """Get database configuration as dictionary."""
        return {
            'host': self.get('DB_HOST'),
            'port': self.get('DB_PORT'),
            'user': self.get('DB_USER'),
            'password': self.get('DB_PASSWORD'),
            'database': self.get('DB_NAME'),
        }
    
    def __repr__(self) -> str:
        """String representation (hide sensitive data)."""
        safe_config = {k: '***' if 'PASSWORD' in k else v 
                       for k, v in self._config.items()}
        return f"Config({safe_config})"


# Global configuration instance
_config_instance: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance


def set_config(config: Config) -> None:
    """Set the global configuration instance (for testing)."""
    global _config_instance
    _config_instance = config
