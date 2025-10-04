"""
Configuration settings for ISC Web DHCP Manager Flask application
All configuration is loaded from /etc/isc-web-dhcp-manager/config.conf
"""

import os


def load_config_file(config_path='/etc/isc-web-dhcp-manager/config.conf'):
    """Load configuration from file and set environment variables"""
    if not os.path.exists(config_path):
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}\n"
            f"Please run the deployment script or create the configuration file manually."
        )

    try:
        with open(config_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                # Parse KEY=VALUE format
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()

                    # Only set if not already set in environment
                    if key and not os.environ.get(key):
                        os.environ[key] = value
    except FileNotFoundError:
        raise
    except Exception as e:
        raise RuntimeError(f"Failed to load config file {config_path}: {e}")


# Load config file on module import into env vars
load_config_file()


class Config:
    """Configuration class - all values loaded from /etc/isc-web-dhcp-manager/config.conf"""

    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY must be set in configuration file")

    DEBUG = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

    # DHCP configuration
    DHCP_CONFIG_PATH = os.environ.get('DHCP_CONFIG_PATH')
    if not DHCP_CONFIG_PATH:
        raise ValueError("DHCP_CONFIG_PATH must be set in configuration file")

    DHCP_BACKUP_DIR = os.environ.get('DHCP_BACKUP_DIR')
    if not DHCP_BACKUP_DIR:
        raise ValueError("DHCP_BACKUP_DIR must be set in configuration file")

    # DHCP service management
    DHCP_SERVICE_NAME = os.environ.get('DHCP_SERVICE_NAME')
    if not DHCP_SERVICE_NAME:
        raise ValueError("DHCP_SERVICE_NAME must be set in configuration file")

    ALLOW_SERVICE_RESTART = os.environ.get('ALLOW_SERVICE_RESTART', 'true').lower() == 'true'

    # API settings
    API_PREFIX = '/api'

    # CORS settings
    CORS_ORIGINS_RAW = os.environ.get('CORS_ORIGINS')
    if not CORS_ORIGINS_RAW:
        raise ValueError("CORS_ORIGINS must be set in configuration file")
    CORS_ORIGINS = CORS_ORIGINS_RAW.split(',')

    # File permissions
    REQUIRE_SUDO = os.environ.get('REQUIRE_SUDO', 'true').lower() == 'true'

    # Validation settings
    MAX_HOSTNAME_LENGTH_RAW = os.environ.get('MAX_HOSTNAME_LENGTH')
    if not MAX_HOSTNAME_LENGTH_RAW:
        raise ValueError("MAX_HOSTNAME_LENGTH must be set in configuration file")
    MAX_HOSTNAME_LENGTH = int(MAX_HOSTNAME_LENGTH_RAW)

    ALLOWED_HOSTNAME_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'

    # Backup settings
    MAX_BACKUPS_RAW = os.environ.get('MAX_BACKUPS')
    if not MAX_BACKUPS_RAW:
        raise ValueError("MAX_BACKUPS must be set in configuration file")
    MAX_BACKUPS = int(MAX_BACKUPS_RAW)


def get_config():
    """Get configuration class"""
    return Config