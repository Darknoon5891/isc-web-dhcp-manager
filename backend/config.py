"""
Configuration settings for DHCP Manager Flask application
"""

import os
from pathlib import Path


class Config:
    """Base configuration class"""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # DHCP configuration
    DHCP_CONFIG_PATH = os.environ.get('DHCP_CONFIG_PATH') or '/etc/dhcp/dhcpd.conf'
    DHCP_BACKUP_DIR = os.environ.get('DHCP_BACKUP_DIR') or '/etc/dhcp/backups'
    
    # DHCP service management
    DHCP_SERVICE_NAME = os.environ.get('DHCP_SERVICE_NAME') or 'isc-dhcp-server'
    ALLOW_SERVICE_RESTART = os.environ.get('ALLOW_SERVICE_RESTART', 'true').lower() == 'true'
    
    # API settings
    API_PREFIX = '/api'
    
    # CORS settings
    CORS_ORIGINS = ['http://localhost:3000', 'http://127.0.0.1:3000']
    
    # File permissions
    REQUIRE_SUDO = os.environ.get('REQUIRE_SUDO', 'true').lower() == 'true'
    
    # Validation settings
    MAX_HOSTNAME_LENGTH = 63
    ALLOWED_HOSTNAME_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'
    
    # Backup settings
    MAX_BACKUPS = int(os.environ.get('MAX_BACKUPS', '10'))
    
    # Development settings
    DEBUG = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    
    # Use a test config file for development
    DHCP_CONFIG_PATH = os.environ.get('DHCP_CONFIG_PATH') or './test_dhcpd.conf'
    DHCP_BACKUP_DIR = os.environ.get('DHCP_BACKUP_DIR') or './test_backups'
    
    # Disable service restart in development
    ALLOW_SERVICE_RESTART = False
    REQUIRE_SUDO = False


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    
    # Production CORS origins (should be configured via environment)
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:3000').split(',')
    
    # Production should use a secure secret key
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY environment variable must be set in production")


class TestConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    
    # Use temporary files for testing
    DHCP_CONFIG_PATH = '/tmp/test_dhcpd.conf'
    DHCP_BACKUP_DIR = '/tmp/test_dhcp_backups'
    
    # Disable service operations in testing
    ALLOW_SERVICE_RESTART = False
    REQUIRE_SUDO = False


# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestConfig,
    'default': DevelopmentConfig
}


def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])


def create_test_config():
    """Create a sample DHCP configuration for testing/development"""
    test_config_content = """# Sample DHCP Configuration for Testing
# Global settings
default-lease-time 600;
max-lease-time 7200;

# Subnet declaration
subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.50 192.168.1.200;
    option routers 192.168.1.1;
    option domain-name-servers 8.8.8.8, 1.1.1.1;
    option domain-name "local";
}

# Static host reservations
host server01 {
    hardware ethernet 00:11:22:33:44:55;
    fixed-address 192.168.1.100;
}

host printer01 {
    hardware ethernet AA:BB:CC:DD:EE:FF;
    fixed-address 192.168.1.101;
}

host workstation01 {
    hardware ethernet 11:22:33:44:55:66;
    fixed-address 192.168.1.102;
}
"""
    
    config_obj = get_config()()
    config_path = Path(config_obj.DHCP_CONFIG_PATH)
    
    # Create directory if it doesn't exist
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Create backup directory
    backup_path = Path(config_obj.DHCP_BACKUP_DIR)
    backup_path.mkdir(parents=True, exist_ok=True)
    
    # Write test configuration
    with open(config_path, 'w') as f:
        f.write(test_config_content)
    
    return str(config_path)