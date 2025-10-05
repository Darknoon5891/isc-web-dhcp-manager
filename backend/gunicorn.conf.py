"""
Gunicorn Configuration for ISC Web DHCP Manager
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from config_manager import ConfigManager

# Server socket
bind = "127.0.0.1:5000"

# Worker processes
workers = 3
worker_class = "sync"
timeout = 120

# Logging
accesslog = "-"  # Log to stdout
errorlog = "-"   # Log to stderr


def on_starting(server):
    """
    Called once when Gunicorn master process starts.
    This is the ideal place for one-time startup logging.
    """
    # Load configuration
    try:
        config_manager = ConfigManager()
        config = config_manager.read_config()

        # Get logging configuration
        log_level = config.get('LOG_LEVEL', 'INFO').upper()
        log_path = config.get('LOGGING_PATH', '/var/log/isc-web-dhcp-manager')

        # Convert log level string to logging constant
        numeric_level = getattr(logging, log_level, logging.INFO)

        # Create log directory if it doesn't exist
        if not os.path.exists(log_path):
            try:
                os.makedirs(log_path, exist_ok=True)
            except PermissionError:
                log_path = '.'

        # Define log format (matching Flask app logging)
        log_format = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # Create rotating file handler
        log_file = os.path.join(log_path, 'dhcp-manager.log')
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(log_format)

        # Create console handler for systemd journal
        console_handler = logging.StreamHandler()
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(log_format)

        # Configure application logger
        logger = logging.getLogger('dhcp-manager-early-startup')
        logger.setLevel(numeric_level)
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        # Log startup information once
        logger.info("=" * 60)
        logger.info("ISC Web DHCP Configuration Manager starting")
        logger.info(f"Workers: {workers}")
        logger.info(f"Bind: {bind}")
        logger.info(f"Worker class: {worker_class}")
        logger.info(f"Timeout: {timeout}s")
        logger.info(f"Log level: {log_level}")
        logger.info(f"Log path: {log_path}")
        logger.info(f"DHCP config path: {config.get('DHCP_CONFIG_PATH', '/etc/dhcp/dhcpd.conf')}")
        logger.info(f"DHCP backup directory: {config.get('DHCP_BACKUP_DIR', '/opt/dhcp-manager/backups')}")
        logger.info(f"API prefix: {config.get('API_PREFIX', '/api')}")
        logger.info(f"CORS origins: {config.get('CORS_ORIGINS', '*')}")
        logger.info(f"Service restart allowed: {config.get('ALLOW_SERVICE_RESTART', 'true')}")
        logger.info("=" * 60)
    except Exception as e:
        # Fallback to basic logging if config fails
        logging.basicConfig(level=logging.INFO)
        logging.error(f"Failed to load configuration during startup: {e}")
        # Don't exit - let the app start anyway
