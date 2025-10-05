"""
ISC Web DHCP Configuration Manager Flask Application
Provides REST API for managing ISC DHCP Server configuration
"""

import os
import subprocess
import socket
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from dhcp_parser import DHCPParser, DHCPHost, DHCPSubnet, DHCPZone, DHCPGlobalConfig
from config_manager import ConfigManager
from tls_manager import get_certificate_info, validate_certificate_file
from auth_manager import hash_password, verify_password, generate_token, verify_token
from lease_parser import LeaseParser, DHCPLease


def setup_logging(app):
    """Configure application logging"""
    # Get logging configuration
    log_level = app.config.get('LOG_LEVEL', 'INFO').upper()
    log_path = app.config.get('LOGGING_PATH', '/var/log/isc-web-dhcp-manager')

    # Convert log level string to logging constant
    numeric_level = getattr(logging, log_level, logging.INFO)

    # Create log directory if it doesn't exist
    if not os.path.exists(log_path):
        try:
            os.makedirs(log_path, exist_ok=True)
        except PermissionError:
            # Fall back to current directory if we can't create log directory
            log_path = '.'

    # Define log format
    log_format = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Create rotating file handler (10MB max, keep 5 backups)
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

    # Configure Flask app logger
    app.logger.setLevel(numeric_level)
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)

    # Configure werkzeug logger (Flask's HTTP server)
    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.setLevel(numeric_level)
    werkzeug_logger.addHandler(file_handler)
    werkzeug_logger.addHandler(console_handler)

    # Set root logger level
    logging.getLogger().setLevel(numeric_level)


def create_app():
    """Application factory"""
    app = Flask(__name__)

    # Load configuration from ConfigManager
    config_manager = ConfigManager()
    config_dict = config_manager.read_config()

    # Load all config values into Flask config
    for key, value in config_dict.items():
        app.config[key] = value

    # Type conversions for specific fields
    if 'FLASK_DEBUG' in app.config:
        app.config['DEBUG'] = app.config['FLASK_DEBUG'].lower() == 'true'

    if 'ALLOW_SERVICE_RESTART' in app.config:
        app.config['ALLOW_SERVICE_RESTART'] = app.config['ALLOW_SERVICE_RESTART'].lower() == 'true'

    if 'REQUIRE_SUDO' in app.config:
        app.config['REQUIRE_SUDO'] = app.config['REQUIRE_SUDO'].lower() == 'true'

    if 'TLS_ENABLED' in app.config:
        app.config['TLS_ENABLED'] = app.config['TLS_ENABLED'].lower() == 'true'

    if 'AUTH_ENABLED' in app.config:
        app.config['AUTH_ENABLED'] = app.config['AUTH_ENABLED'].lower() == 'true'

    if 'MAX_HOSTNAME_LENGTH' in app.config:
        app.config['MAX_HOSTNAME_LENGTH'] = int(app.config['MAX_HOSTNAME_LENGTH'])

    if 'MAX_BACKUPS' in app.config:
        app.config['MAX_BACKUPS'] = int(app.config['MAX_BACKUPS'])

    if 'AUTH_TOKEN_EXPIRY_HOURS' in app.config:
        app.config['AUTH_TOKEN_EXPIRY_HOURS'] = int(app.config['AUTH_TOKEN_EXPIRY_HOURS'])

    if 'MAX_CONTENT_LENGTH' in app.config:
        app.config['MAX_CONTENT_LENGTH'] = int(app.config['MAX_CONTENT_LENGTH'])

    # Parse CORS_ORIGINS into list
    if 'CORS_ORIGINS' in app.config:
        app.config['CORS_ORIGINS'] = app.config['CORS_ORIGINS'].split(',')

    # Validate required fields exist
    required_fields = ['SECRET_KEY', 'DHCP_CONFIG_PATH', 'DHCP_BACKUP_DIR', 'DHCP_SERVICE_NAME', 'API_PREFIX']
    for field in required_fields:
        if not app.config.get(field):
            raise ValueError(f"{field} must be set in configuration file")

    # Initialize CORS
    CORS(app, origins=app.config['CORS_ORIGINS'])

    # Setup logging
    setup_logging(app)

    # Log minimal worker initialization info
    app.logger.debug(f"Worker process {os.getpid()} initialized")

    # Initialize DHCP parser
    dhcp_parser = DHCPParser(app.config['DHCP_CONFIG_PATH'])

    # Add security headers to all responses
    @app.after_request
    def add_security_headers(response):
        """Add security headers to all API responses"""
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # Prevent clickjacking (API shouldn't be framed)
        response.headers['X-Frame-Options'] = 'DENY'

        # Enable XSS protection
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # Referrer policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Content Security Policy for API (restrictive)
        response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"

        # Prevent caching of sensitive data
        if request.path.startswith(app.config.get('API_PREFIX', '/api')):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'

        return response

    @app.errorhandler(400)
    def bad_request(error):
        app.logger.warning(f"Bad request: {request.method} {request.path} - {str(error)}")
        return jsonify({'error': 'Bad request', 'message': str(error)}), 400

    @app.errorhandler(404)
    def not_found(error):
        app.logger.debug(f"Not found: {request.method} {request.path}")
        return jsonify({'error': 'Not found', 'message': str(error)}), 404

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal server error: {request.method} {request.path} - {str(error)}", exc_info=True)
        return jsonify({'error': 'Internal server error', 'message': str(error)}), 500

    # Authentication decorator
    def require_auth(f):
        """Decorator to require authentication for endpoints"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Skip authentication if AUTH_ENABLED is false
            if not app.config.get('AUTH_ENABLED', False):
                return f(*args, **kwargs)

            # Get token from Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                app.logger.warning(f"Unauthorized access attempt to {request.path} - no token provided")
                return jsonify({'error': 'Authentication required', 'message': 'No authorization token provided'}), 401

            # Extract token (format: "Bearer <token>")
            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                app.logger.warning(f"Unauthorized access attempt to {request.path} - invalid token format")
                return jsonify({'error': 'Authentication required', 'message': 'Invalid authorization header format'}), 401

            token = parts[1]

            # Verify token
            is_valid, error_message = verify_token(token, app.config['SECRET_KEY'])
            if not is_valid:
                app.logger.warning(f"Unauthorized access attempt to {request.path} - {error_message}")
                return jsonify({'error': 'Authentication required', 'message': error_message}), 401

            return f(*args, **kwargs)
        return decorated_function

    # Authentication endpoints (not protected)
    @app.route(f"{app.config['API_PREFIX']}/auth/login", methods=['POST'])
    def login():
        """Authenticate and receive JWT token"""
        try:
            data = request.get_json()
            if not data or 'password' not in data:
                app.logger.warning("Login attempt with missing password")
                return jsonify({'error': 'Password required'}), 400

            password = data['password']

            # Check if authentication is enabled
            if not app.config.get('AUTH_ENABLED', False):
                app.logger.warning("Login attempt when authentication is disabled")
                return jsonify({'error': 'Authentication is not enabled'}), 400

            # Get password hash from config
            password_hash = app.config.get('AUTH_PASSWORD_HASH', '')
            if not password_hash:
                app.logger.error("Authentication enabled but no password hash configured")
                return jsonify({'error': 'Authentication not properly configured'}), 500

            # Verify password
            if not verify_password(password, password_hash):
                app.logger.warning("Failed login attempt - incorrect password")
                return jsonify({'error': 'Invalid password'}), 401

            # Generate token
            expiry_hours = app.config.get('AUTH_TOKEN_EXPIRY_HOURS', 24)
            token, expires_at = generate_token(app.config['SECRET_KEY'], expiry_hours)

            app.logger.info("Successful login")
            return jsonify({
                'token': token,
                'expires_at': expires_at
            })

        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            return jsonify({'error': 'Login failed', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/auth/verify", methods=['POST'])
    def verify_auth():
        """Verify if authentication token is valid"""
        try:
            # Get token from Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({'valid': False})

            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return jsonify({'valid': False})

            token = parts[1]

            # Verify token
            is_valid, _ = verify_token(token, app.config['SECRET_KEY'])

            app.logger.debug(f"Token verification: {is_valid}")
            return jsonify({'valid': is_valid})

        except Exception as e:
            app.logger.error(f"Token verification error: {str(e)}")
            return jsonify({'valid': False})

    @app.route(f"{app.config['API_PREFIX']}/auth/change-password", methods=['POST'])
    @require_auth
    def change_password():
        """Change authentication password"""
        try:
            data = request.get_json()
            if not data or 'current_password' not in data or 'new_password' not in data:
                app.logger.warning("Password change attempt with missing fields")
                return jsonify({'error': 'Current password and new password required'}), 400

            current_password = data['current_password']
            new_password = data['new_password']

            # Validate new password
            if len(new_password) < 8:
                app.logger.warning("Password change attempt with password too short")
                return jsonify({'error': 'New password must be at least 8 characters'}), 400

            # Get current password hash
            current_hash = app.config.get('AUTH_PASSWORD_HASH', '')
            if not current_hash:
                app.logger.error("Password change attempt but no hash configured")
                return jsonify({'error': 'Authentication not properly configured'}), 500

            # Verify current password
            if not verify_password(current_password, current_hash):
                app.logger.warning("Password change attempt with incorrect current password")
                return jsonify({'error': 'Current password is incorrect'}), 401

            # Generate new hash
            new_hash = hash_password(new_password)

            # Update config
            config = config_manager.read_config()
            config['AUTH_PASSWORD_HASH'] = new_hash
            config_manager.write_config(config)

            app.logger.info("Password changed successfully, initiating backend service restart")

            # Restart backend service asynchronously to apply new password
            # We can't wait for response because the service will kill itself
            subprocess.Popen(
                ['/usr/bin/sudo', '/bin/systemctl', 'restart', 'dhcp-manager.service'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            return jsonify({
                'message': 'Password changed successfully. Backend service is restarting to apply changes.'
            })

        except Exception as e:
            app.logger.error(f"Password change error: {str(e)}")
            return jsonify({'error': 'Failed to change password', 'message': str(e)}), 500

    @app.route('/')
    @app.route(f"{app.config['API_PREFIX']}/")
    def index():
        """Health check endpoint"""
        app.logger.debug("Health check accessed")
        return jsonify({
            'status': 'running',
            'service': 'ISC Web DHCP Configuration Manager',
            'version': '1.0.0'
        })

    @app.route(f"{app.config['API_PREFIX']}/system/hostname", methods=['GET'])
    @require_auth
    def get_system_hostname():
        """Get the server hostname"""
        try:
            hostname = socket.gethostname()
            app.logger.debug(f"System hostname retrieved: {hostname}")
            return jsonify({'hostname': hostname})
        except Exception as e:
            app.logger.error(f"Failed to get system hostname: {str(e)}")
            return jsonify({'error': 'Failed to get hostname', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/hosts", methods=['GET'])
    @require_auth
    def get_hosts():
        """Get all DHCP host reservations"""
        try:
            hosts = dhcp_parser.parse_hosts()
            app.logger.debug(f"Retrieved {len(hosts)} host reservations")
            return jsonify([host.to_dict() for host in hosts])
        except PermissionError:
            app.logger.error("Permission denied accessing DHCP configuration for host list")
            return jsonify({'error': 'Permission denied accessing DHCP configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to read hosts: {str(e)}")
            return jsonify({'error': 'Failed to read hosts', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/hosts/<hostname>", methods=['GET'])
    @require_auth
    def get_host(hostname):
        """Get a specific host reservation"""
        try:
            # Validate hostname parameter
            if not dhcp_parser.validate_hostname(hostname):
                app.logger.warning(f"Invalid hostname in URL: {hostname}")
                return jsonify({'error': 'Invalid hostname format'}), 400

            host = dhcp_parser.get_host(hostname)
            if host:
                app.logger.debug(f"Retrieved host: {hostname}")
                return jsonify(host.to_dict())
            app.logger.debug(f"Host not found: {hostname}")
            return jsonify({'error': 'Host not found'}), 404
        except PermissionError:
            app.logger.error(f"Permission denied accessing DHCP configuration for host: {hostname}")
            return jsonify({'error': 'Permission denied accessing DHCP configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to read host {hostname}: {str(e)}")
            return jsonify({'error': 'Failed to read host', 'message': str(e)}), 500
    
    @app.route(f"{app.config['API_PREFIX']}/hosts", methods=['POST'])
    @require_auth
    def add_host():
        """Add a new host reservation"""
        try:
            data = request.get_json()
            if not data:
                app.logger.warning("Add host request with no JSON data")
                return jsonify({'error': 'No JSON data provided'}), 400

            hostname = data.get('hostname')
            mac = data.get('mac')
            ip = data.get('ip')

            if not all([hostname, mac, ip]):
                app.logger.warning(f"Add host request missing required fields: hostname={hostname}, mac={mac}, ip={ip}")
                return jsonify({'error': 'hostname, mac, and ip are required'}), 400

            # Validate input lengths
            if len(hostname) > app.config['MAX_HOSTNAME_LENGTH']:
                app.logger.warning(f"Hostname too long: {len(hostname)} > {app.config['MAX_HOSTNAME_LENGTH']}")
                return jsonify({'error': f'Hostname too long (max {app.config["MAX_HOSTNAME_LENGTH"]} characters)'}), 400

            dhcp_parser.add_host(hostname, mac, ip)
            app.logger.info(f"Added host reservation: {hostname} - MAC: {mac}, IP: {ip}")

            # Return the created host
            new_host = dhcp_parser.get_host(hostname)
            return jsonify(new_host.to_dict()), 201

        except ValueError as e:
            app.logger.warning(f"Validation error adding host: {str(e)}")
            return jsonify({'error': 'Validation error', 'message': str(e)}), 400
        except PermissionError:
            app.logger.error("Permission denied adding host reservation")
            return jsonify({'error': 'Permission denied modifying DHCP configuration',}), 403
        except Exception as e:
            app.logger.error(f"Failed to add host: {str(e)}")
            return jsonify({'error': 'Failed to add host', 'message': str(e)}), 500
    
    @app.route(f"{app.config['API_PREFIX']}/hosts/<hostname>", methods=['PUT'])
    @require_auth
    def update_host(hostname):
        """Update an existing host reservation"""
        try:
            # Validate hostname parameter
            if not dhcp_parser.validate_hostname(hostname):
                app.logger.warning(f"Invalid hostname in URL: {hostname}")
                return jsonify({'error': 'Invalid hostname format'}), 400

            data = request.get_json()
            if not data:
                app.logger.warning(f"Update host request for {hostname} with no JSON data")
                return jsonify({'error': 'No JSON data provided'}), 400

            new_mac = data.get('mac')
            new_ip = data.get('ip')

            if not new_mac and not new_ip:
                app.logger.warning(f"Update host request for {hostname} with no changes provided")
                return jsonify({'error': 'At least one of mac or ip must be provided'}), 400

            changes = []
            if new_mac:
                changes.append(f"MAC: {new_mac}")
            if new_ip:
                changes.append(f"IP: {new_ip}")

            dhcp_parser.update_host(hostname, new_mac, new_ip)
            app.logger.info(f"Updated host reservation: {hostname} - {', '.join(changes)}")

            # Return the updated host
            updated_host = dhcp_parser.get_host(hostname)
            return jsonify(updated_host.to_dict())

        except ValueError as e:
            app.logger.warning(f"Validation error updating host {hostname}: {str(e)}")
            return jsonify({'error': 'Validation error', 'message': str(e)}), 400
        except PermissionError:
            app.logger.error(f"Permission denied updating host: {hostname}")
            return jsonify({'error': 'Permission denied modifying DHCP configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to update host {hostname}: {str(e)}")
            return jsonify({'error': 'Failed to update host', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/hosts/<hostname>", methods=['DELETE'])
    @require_auth
    def delete_host(hostname):
        """Delete a host reservation"""
        try:
            # Validate hostname parameter
            if not dhcp_parser.validate_hostname(hostname):
                app.logger.warning(f"Invalid hostname in URL: {hostname}")
                return jsonify({'error': 'Invalid hostname format'}), 400

            dhcp_parser.delete_host(hostname)
            app.logger.info(f"Deleted host reservation: {hostname}")
            return jsonify({'message': f'Host {hostname} deleted successfully'})

        except ValueError as e:
            app.logger.warning(f"Validation error deleting host {hostname}: {str(e)}")
            return jsonify({'error': 'Validation error', 'message': str(e)}), 404
        except PermissionError:
            app.logger.error(f"Permission denied deleting host: {hostname}")
            return jsonify({'error': 'Permission denied modifying DHCP configuration',}), 403
        except Exception as e:
            app.logger.error(f"Failed to delete host {hostname}: {str(e)}")
            return jsonify({'error': 'Failed to delete host', 'message': str(e)}), 500
    
    @app.route(f"{app.config['API_PREFIX']}/config", methods=['GET'])
    @require_auth
    def get_config_content():
        """Get the raw DHCP configuration content"""
        try:
            content = dhcp_parser.read_config()
            app.logger.debug(f"DHCP config file read, size: {len(content)} bytes")
            return jsonify({'config': content})
        except PermissionError:
            app.logger.error("Permission denied reading DHCP configuration")
            return jsonify({'error': 'Permission denied accessing DHCP configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to read DHCP configuration: {str(e)}")
            return jsonify({'error': 'Failed to read configuration', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/validate", methods=['POST'])
    @require_auth
    def validate_config():
        """Validate the current DHCP configuration"""
        try:
            is_valid, message = dhcp_parser.validate_config()
            app.logger.info(f"DHCP config validation: {'VALID' if is_valid else 'INVALID'} - {message}")
            return jsonify({
                'valid': is_valid,
                'message': message
            })
        except Exception as e:
            app.logger.error(f"Failed to validate DHCP configuration: {str(e)}")
            return jsonify({'error': 'Failed to validate configuration', 'message': str(e)}), 500
    
    @app.route(f"{app.config['API_PREFIX']}/restart/<service_name>", methods=['POST'])
    @require_auth
    def restart_service(service_name):
        """Restart a service (DHCP, backend, or nginx)"""
        if not app.config['ALLOW_SERVICE_RESTART']:
            app.logger.warning(f"Service restart attempt blocked - restart disabled: {service_name}")
            return jsonify({'error': 'Service restart is disabled'}), 403

        try:
            # Validate service name - only allow these services
            allowed_services = ['isc-dhcp-server', 'dhcp-manager', 'nginx']
            if service_name not in allowed_services:
                app.logger.warning(f"Invalid service restart request: {service_name}")
                return jsonify({
                    'error': 'Invalid service name',
                    'message': f'Service must be one of: {", ".join(allowed_services)}'
                }), 400

            full_service_name = f'{service_name}.service' if not service_name.endswith('.service') else service_name

            # Validate DHCP config before restarting DHCP service
            if service_name == 'isc-dhcp-server':
                is_valid, validation_message = dhcp_parser.validate_config()
                if not is_valid:
                    app.logger.warning(f"DHCP restart blocked - config validation failed: {validation_message}")
                    return jsonify({
                        'error': 'Configuration validation failed',
                        'message': validation_message
                    }), 400

            # Validate nginx config before reloading nginx
            if service_name == 'nginx':
                app.logger.info("Testing nginx configuration before reload")
                test_result = subprocess.run(
                    ['/usr/bin/sudo', '/usr/sbin/nginx', '-t'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if test_result.returncode != 0:
                    error_msg = test_result.stderr.strip() if test_result.stderr else "Configuration test failed"
                    app.logger.error(f"Nginx configuration test failed: {error_msg}")
                    return jsonify({
                        'error': 'Nginx configuration test failed',
                        'message': error_msg
                    }), 400

            # Special handling for backend service restart
            if service_name == 'dhcp-manager':
                # For backend service, initiate restart asynchronously and return immediately
                # We can't wait for response because the service will kill itself
                app.logger.info(f"Initiating backend service restart: {full_service_name}")
                subprocess.Popen(
                    ['/usr/bin/sudo', '/bin/systemctl', 'restart', full_service_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                return jsonify({
                    'message': f'Service {full_service_name} restart initiated successfully',
                    'status': 'restarting'
                })

            # For nginx, use reload instead of restart
            if service_name == 'nginx':
                app.logger.info(f"Reloading nginx service: {full_service_name}")
                result = subprocess.run(
                    ['/usr/bin/sudo', '/bin/systemctl', 'reload', full_service_name],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            else:
                # For DHCP service, use synchronous restart with status checking
                app.logger.info(f"Restarting service: {full_service_name}")
                result = subprocess.run(
                    ['/usr/bin/sudo', '/bin/systemctl', 'restart', full_service_name],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

            if result.returncode == 0:
                # Check if service is running
                # Note: is-active returns non-zero if service is not active - this is normal
                status_result = subprocess.run(
                    ['/bin/systemctl', 'is-active', full_service_name],
                    capture_output=True,
                    text=True
                )

                service_status = status_result.stdout.strip()

                if service_status == 'active':
                    action = 'reloaded' if service_name == 'nginx' else 'restarted'
                    app.logger.info(f"Service {action} successfully: {full_service_name} - status: {service_status}")
                    return jsonify({
                        'message': f'Service {full_service_name} {action} successfully',
                        'status': 'active'
                    })
                else:
                    error_msg = f'Service restart failed - service is {service_status}'
                    if result.stderr:
                        error_msg += f'\n{result.stderr.strip()}'
                    app.logger.error(f"Service restart failed: {full_service_name} - {error_msg}")
                    return jsonify({
                        'error': error_msg,
                        'message': error_msg,
                        'status': service_status
                    }), 500
            else:
                error_msg = result.stderr.strip() if result.stderr else f'Failed to restart service {full_service_name}'
                app.logger.error(f"Service restart command failed: {full_service_name} - {error_msg}")
                return jsonify({
                    'error': error_msg,
                    'message': error_msg
                }), 500

        except subprocess.TimeoutExpired:
            app.logger.error(f"Service restart timed out: {service_name}")
            return jsonify({'error': 'Service restart timed out', 'message': 'Service restart timed out'}), 500
        except PermissionError:
            app.logger.error(f"Permission denied restarting service: {service_name}")
            return jsonify({'error': 'Permission denied - sudo access required', 'message': 'Permission denied - sudo access required'}), 403
        except FileNotFoundError as e:
            app.logger.error(f"Command not found while restarting service {service_name}: {e.filename}")
            return jsonify({'error': f'Command not found: {e.filename}', 'message': f'Command not found: {e.filename}'}), 500
        except Exception as e:
            app.logger.error(f"Unexpected error restarting service {service_name}: {str(e)}")
            return jsonify({'error': 'Failed to restart service', 'message': str(e)}), 500
    
    @app.route(f"{app.config['API_PREFIX']}/service/status/<service_name>", methods=['GET'])
    @require_auth
    def get_service_status(service_name):
        """Get the current status of a service (DHCP, backend, or nginx)"""
        try:
            # Validate service name - only allow these services
            allowed_services = ['isc-dhcp-server', 'dhcp-manager', 'nginx']
            if service_name not in allowed_services:
                app.logger.warning(f"Invalid service status request: {service_name}")
                return jsonify({
                    'error': 'Invalid service name',
                    'message': f'Service must be one of: {", ".join(allowed_services)}'
                }), 400

            full_service_name = f'{service_name}.service' if not service_name.endswith('.service') else service_name

            # Get service status (polkit handles authentication)
            # Note: is-active returns non-zero if service is not active - this is normal
            result = subprocess.run(
                ['/bin/systemctl', 'is-active', full_service_name],
                capture_output=True,
                text=True
            )

            status = result.stdout.strip()

            # Get more detailed status
            # Note: status returns non-zero if service is not active - this is normal
            detail_result = subprocess.run(
                ['/bin/systemctl', 'status', full_service_name, '--no-pager', '-l'],
                capture_output=True,
                text=True
            )

            app.logger.debug(f"Service status checked: {full_service_name} - {status}")

            return jsonify({
                'service': full_service_name,
                'status': status,
                'active': status == 'active',
                'details': detail_result.stdout
            })

        except FileNotFoundError:
            app.logger.error("systemctl command not found")
            return jsonify({'error': 'systemctl command not found', 'message': 'systemctl not available at /bin/systemctl'}), 500
        except Exception as e:
            app.logger.error(f"Failed to get service status for {service_name}: {str(e)}")
            return jsonify({'error': 'Failed to get service status', 'message': str(e)}), 500
    
    @app.route(f"{app.config['API_PREFIX']}/backups", methods=['GET'])
    @require_auth
    def list_backups():
        """List available configuration backups"""
        try:
            backup_dir = app.config['DHCP_BACKUP_DIR']

            # Validate backup directory to prevent path traversal
            backup_dir = os.path.abspath(backup_dir)
            if not os.path.exists(backup_dir):
                return jsonify([])

            # Ensure backup_dir is a directory
            if not os.path.isdir(backup_dir):
                return jsonify({'error': 'Backup directory is not a directory'}), 500

            backups = []
            for filename in os.listdir(backup_dir):
                # Sanitize filename - only allow expected backup files
                if not filename.startswith('dhcpd.conf.backup_'):
                    continue

                # Prevent path traversal in filename
                if '..' in filename or '/' in filename or '\\' in filename:
                    continue

                backup_path = os.path.join(backup_dir, filename)

                # Ensure the resolved path is still within backup_dir
                if not os.path.abspath(backup_path).startswith(backup_dir):
                    continue

                # Only include regular files
                if not os.path.isfile(backup_path):
                    continue

                stat = os.stat(backup_path)
                backups.append({
                    'filename': filename,
                    'timestamp': stat.st_mtime,
                    'size': stat.st_size
                })

            # Sort by timestamp, newest first
            backups.sort(key=lambda x: x['timestamp'], reverse=True)

            app.logger.debug(f"Listed {len(backups)} backup files")
            return jsonify(backups)

        except Exception as e:
            app.logger.error(f"Failed to list backups: {str(e)}")
            return jsonify({'error': 'Failed to list backups', 'message': str(e)}), 500

    # Subnet management endpoints
    @app.route(f"{app.config['API_PREFIX']}/subnets", methods=['GET'])
    @require_auth
    def get_subnets():
        """Get all subnet declarations"""
        try:
            subnets = dhcp_parser.parse_subnets()
            app.logger.debug(f"Retrieved {len(subnets)} subnet declarations")
            return jsonify([subnet.to_dict() for subnet in subnets])
        except PermissionError:
            app.logger.error("Permission denied accessing DHCP configuration for subnet list")
            return jsonify({'error': 'Permission denied accessing DHCP configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to read subnets: {str(e)}")
            return jsonify({'error': 'Failed to read subnets', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/subnets/<network>", methods=['GET'])
    @require_auth
    def get_subnet(network):
        """Get a specific subnet"""
        try:
            # Validate network parameter
            if not dhcp_parser.validate_ip_address(network):
                app.logger.warning(f"Invalid network address in URL: {network}")
                return jsonify({'error': 'Invalid network address format'}), 400

            subnet = dhcp_parser.get_subnet(network)
            if subnet:
                app.logger.debug(f"Retrieved subnet: {network}")
                return jsonify(subnet.to_dict())
            app.logger.debug(f"Subnet not found: {network}")
            return jsonify({'error': 'Subnet not found'}), 404
        except PermissionError:
            app.logger.error(f"Permission denied accessing DHCP configuration for subnet: {network}")
            return jsonify({'error': 'Permission denied accessing DHCP configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to read subnet {network}: {str(e)}")
            return jsonify({'error': 'Failed to read subnet', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/subnets", methods=['POST'])
    @require_auth
    def add_subnet():
        """Add a new subnet"""
        try:
            data = request.get_json()
            if not data:
                app.logger.warning("Add subnet request with no JSON data")
                return jsonify({'error': 'No JSON data provided'}), 400

            network = data.get('network')
            netmask = data.get('netmask')
            range_start = data.get('range_start')
            range_end = data.get('range_end')
            options = data.get('options', {})

            if not all([network, netmask]):
                app.logger.warning(f"Add subnet request missing required fields: network={network}, netmask={netmask}")
                return jsonify({'error': 'network and netmask are required'}), 400

            dhcp_parser.add_subnet(network, netmask, range_start, range_end, options)
            app.logger.info(f"Added subnet: {network}/{netmask}")

            # Return the created subnet
            new_subnet = dhcp_parser.get_subnet(network)
            return jsonify(new_subnet.to_dict()), 201

        except ValueError as e:
            app.logger.warning(f"Validation error adding subnet: {str(e)}")
            return jsonify({'error': 'Validation error', 'message': str(e)}), 400
        except PermissionError:
            app.logger.error("Permission denied adding subnet")
            return jsonify({'error': 'Permission denied writing DHCP configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to add subnet: {str(e)}")
            return jsonify({'error': 'Failed to add subnet', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/subnets/<network>", methods=['PUT'])
    @require_auth
    def update_subnet(network):
        """Update an existing subnet"""
        try:
            # Validate network parameter
            if not dhcp_parser.validate_ip_address(network):
                app.logger.warning(f"Invalid network address in URL: {network}")
                return jsonify({'error': 'Invalid network address format'}), 400

            data = request.get_json()
            if not data:
                app.logger.warning(f"Update subnet request for {network} with no JSON data")
                return jsonify({'error': 'No JSON data provided'}), 400

            new_netmask = data.get('netmask')
            new_range_start = data.get('range_start')
            new_range_end = data.get('range_end')
            new_options = data.get('options')

            dhcp_parser.update_subnet(network, new_netmask, new_range_start, new_range_end, new_options)
            app.logger.info(f"Updated subnet: {network}")

            # Return the updated subnet
            updated_subnet = dhcp_parser.get_subnet(network)
            return jsonify(updated_subnet.to_dict())

        except ValueError as e:
            app.logger.warning(f"Validation error updating subnet {network}: {str(e)}")
            return jsonify({'error': 'Validation error', 'message': str(e)}), 400
        except PermissionError:
            app.logger.error(f"Permission denied updating subnet: {network}")
            return jsonify({'error': 'Permission denied writing DHCP configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to update subnet {network}: {str(e)}")
            return jsonify({'error': 'Failed to update subnet', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/subnets/<network>", methods=['DELETE'])
    @require_auth
    def delete_subnet(network):
        """Delete a subnet"""
        try:
            # Validate network parameter
            if not dhcp_parser.validate_ip_address(network):
                app.logger.warning(f"Invalid network address in URL: {network}")
                return jsonify({'error': 'Invalid network address format'}), 400

            dhcp_parser.delete_subnet(network)
            app.logger.info(f"Deleted subnet: {network}")
            return jsonify({'message': f'Subnet {network} deleted successfully'})

        except ValueError as e:
            app.logger.warning(f"Validation error deleting subnet {network}: {str(e)}")
            return jsonify({'error': 'Validation error', 'message': str(e)}), 404
        except PermissionError:
            app.logger.error(f"Permission denied deleting subnet: {network}")
            return jsonify({'error': 'Permission denied writing DHCP configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to delete subnet {network}: {str(e)}")
            return jsonify({'error': 'Failed to delete subnet', 'message': str(e)}), 500

    # Zone management endpoints
    @app.route(f"{app.config['API_PREFIX']}/zones", methods=['GET'])
    @require_auth
    def get_zones():
        """Get all zone declarations"""
        try:
            zones = dhcp_parser.parse_zones()
            app.logger.debug(f"Retrieved {len(zones)} zone declarations")
            return jsonify([zone.to_dict() for zone in zones])
        except PermissionError:
            app.logger.error("Permission denied accessing DHCP configuration for zone list")
            return jsonify({'error': 'Permission denied accessing DHCP configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to read zones: {str(e)}")
            return jsonify({'error': 'Failed to read zones', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/zones/<zone_name>", methods=['GET'])
    @require_auth
    def get_zone(zone_name):
        """Get a specific zone"""
        try:
            # Validate zone_name parameter
            if not dhcp_parser.validate_zone_name(zone_name):
                app.logger.warning(f"Invalid zone name in URL: {zone_name}")
                return jsonify({'error': 'Invalid zone name format'}), 400

            zone = dhcp_parser.get_zone(zone_name)
            if zone:
                app.logger.debug(f"Retrieved zone: {zone_name}")
                return jsonify(zone.to_dict())
            app.logger.debug(f"Zone not found: {zone_name}")
            return jsonify({'error': 'Zone not found'}), 404
        except PermissionError:
            app.logger.error(f"Permission denied accessing DHCP configuration for zone: {zone_name}")
            return jsonify({'error': 'Permission denied accessing DHCP configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to read zone {zone_name}: {str(e)}")
            return jsonify({'error': 'Failed to read zone', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/zones", methods=['POST'])
    @require_auth
    def add_zone():
        """Add a new zone"""
        try:
            data = request.get_json()
            if not data:
                app.logger.warning("Add zone request with no JSON data")
                return jsonify({'error': 'No JSON data provided'}), 400

            zone_name = data.get('zone_name')
            primary = data.get('primary')
            key_name = data.get('key_name')
            secondary = data.get('secondary', [])

            if not all([zone_name, primary]):
                app.logger.warning(f"Add zone request missing required fields: zone_name={zone_name}, primary={primary}")
                return jsonify({'error': 'zone_name and primary are required'}), 400

            dhcp_parser.add_zone(zone_name, primary, key_name, secondary)
            app.logger.info(f"Added zone: {zone_name} (primary: {primary})")

            # Return the created zone
            new_zone = dhcp_parser.get_zone(zone_name)
            return jsonify(new_zone.to_dict()), 201

        except ValueError as e:
            app.logger.warning(f"Validation error adding zone: {str(e)}")
            return jsonify({'error': 'Validation error', 'message': str(e)}), 400
        except PermissionError:
            app.logger.error("Permission denied adding zone")
            return jsonify({'error': 'Permission denied writing DHCP configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to add zone: {str(e)}")
            return jsonify({'error': 'Failed to add zone', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/zones/<zone_name>", methods=['PUT'])
    @require_auth
    def update_zone(zone_name):
        """Update an existing zone"""
        try:
            # Validate zone_name parameter
            if not dhcp_parser.validate_zone_name(zone_name):
                app.logger.warning(f"Invalid zone name in URL: {zone_name}")
                return jsonify({'error': 'Invalid zone name format'}), 400

            data = request.get_json()
            if not data:
                app.logger.warning(f"Update zone request for {zone_name} with no JSON data")
                return jsonify({'error': 'No JSON data provided'}), 400

            new_primary = data.get('primary')
            new_key_name = data.get('key_name')
            new_secondary = data.get('secondary')

            dhcp_parser.update_zone(zone_name, new_primary, new_key_name, new_secondary)
            app.logger.info(f"Updated zone: {zone_name}")

            # Return the updated zone
            updated_zone = dhcp_parser.get_zone(zone_name)
            return jsonify(updated_zone.to_dict())

        except ValueError as e:
            app.logger.warning(f"Validation error updating zone {zone_name}: {str(e)}")
            return jsonify({'error': 'Validation error', 'message': str(e)}), 400
        except PermissionError:
            app.logger.error(f"Permission denied updating zone: {zone_name}")
            return jsonify({'error': 'Permission denied writing DHCP configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to update zone {zone_name}: {str(e)}")
            return jsonify({'error': 'Failed to update zone', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/zones/<zone_name>", methods=['DELETE'])
    @require_auth
    def delete_zone(zone_name):
        """Delete a zone"""
        try:
            # Validate zone_name parameter
            if not dhcp_parser.validate_zone_name(zone_name):
                app.logger.warning(f"Invalid zone name in URL: {zone_name}")
                return jsonify({'error': 'Invalid zone name format'}), 400

            dhcp_parser.delete_zone(zone_name)
            app.logger.info(f"Deleted zone: {zone_name}")
            return jsonify({'message': f'Zone {zone_name} deleted successfully'})

        except ValueError as e:
            app.logger.warning(f"Validation error deleting zone {zone_name}: {str(e)}")
            return jsonify({'error': 'Validation error', 'message': str(e)}), 404
        except PermissionError:
            app.logger.error(f"Permission denied deleting zone: {zone_name}")
            return jsonify({'error': 'Permission denied writing DHCP configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to delete zone {zone_name}: {str(e)}")
            return jsonify({'error': 'Failed to delete zone', 'message': str(e)}), 500

    # Lease viewing endpoints
    @app.route(f"{app.config['API_PREFIX']}/leases", methods=['GET'])
    @require_auth
    def get_leases():
        """Get all DHCP leases"""
        try:
            leases_path = app.config.get('DHCP_LEASES_PATH', '/var/lib/dhcp/dhcpd.leases')
            lease_parser = LeaseParser(leases_path)
            leases = lease_parser.get_all_leases()

            # Convert dataclasses to dicts
            leases_dict = [
                {
                    'ip': lease.ip,
                    'mac': lease.mac,
                    'starts': lease.starts,
                    'ends': lease.ends,
                    'state': lease.state,
                    'hostname': lease.hostname,
                    'binding_state': lease.binding_state
                }
                for lease in leases
            ]

            app.logger.debug(f"Retrieved {len(leases_dict)} leases")
            return jsonify(leases_dict)

        except FileNotFoundError:
            app.logger.error(f"Leases file not found: {app.config.get('DHCP_LEASES_PATH')}")
            return jsonify({'error': 'Leases file not found'}), 404
        except PermissionError:
            app.logger.error("Permission denied accessing leases file")
            return jsonify({'error': 'Permission denied accessing leases file'}), 403
        except Exception as e:
            app.logger.error(f"Failed to read leases: {str(e)}")
            return jsonify({'error': 'Failed to read leases', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/leases/active", methods=['GET'])
    @require_auth
    def get_active_leases():
        """Get only active DHCP leases"""
        try:
            leases_path = app.config.get('DHCP_LEASES_PATH', '/var/lib/dhcp/dhcpd.leases')
            lease_parser = LeaseParser(leases_path)
            leases = lease_parser.get_active_leases()

            # Convert dataclasses to dicts
            leases_dict = [
                {
                    'ip': lease.ip,
                    'mac': lease.mac,
                    'starts': lease.starts,
                    'ends': lease.ends,
                    'state': lease.state,
                    'hostname': lease.hostname,
                    'binding_state': lease.binding_state
                }
                for lease in leases
            ]

            app.logger.debug(f"Retrieved {len(leases_dict)} active leases")
            return jsonify(leases_dict)

        except FileNotFoundError:
            app.logger.error(f"Leases file not found: {app.config.get('DHCP_LEASES_PATH')}")
            return jsonify({'error': 'Leases file not found'}), 404
        except PermissionError:
            app.logger.error("Permission denied accessing leases file")
            return jsonify({'error': 'Permission denied accessing leases file'}), 403
        except Exception as e:
            app.logger.error(f"Failed to read active leases: {str(e)}")
            return jsonify({'error': 'Failed to read active leases', 'message': str(e)}), 500

    # Global configuration endpoints
    @app.route(f"{app.config['API_PREFIX']}/global-config", methods=['GET'])
    @require_auth
    def get_global_config():
        """Get global DHCP configuration settings"""
        try:
            config = dhcp_parser.parse_global_config()
            app.logger.debug("Retrieved global DHCP configuration")
            return jsonify(config.to_dict())
        except PermissionError:
            app.logger.error("Permission denied accessing global DHCP configuration")
            return jsonify({'error': 'Permission denied accessing DHCP configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to read global DHCP configuration: {str(e)}")
            return jsonify({'error': 'Failed to read global configuration', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/global-config", methods=['PUT'])
    @require_auth
    def update_global_config():
        """Update global DHCP configuration settings"""
        try:
            data = request.get_json()
            if not data:
                app.logger.warning("Update global config request with no JSON data")
                return jsonify({'error': 'No JSON data provided'}), 400

            # Create DHCPGlobalConfig object from request data
            config = DHCPGlobalConfig(
                default_lease_time=data.get('default_lease_time', 600),
                max_lease_time=data.get('max_lease_time', 7200),
                authoritative=data.get('authoritative', False),
                log_facility=data.get('log_facility'),
                domain_name=data.get('domain_name'),
                domain_name_servers=data.get('domain_name_servers'),
                ntp_servers=data.get('ntp_servers'),
                time_offset=data.get('time_offset'),
                ddns_update_style=data.get('ddns_update_style', 'none'),
                ping_check=data.get('ping_check', False),
                ping_timeout=data.get('ping_timeout')
            )

            dhcp_parser.update_global_config(config)
            app.logger.info("Updated global DHCP configuration")
            updated_config = dhcp_parser.parse_global_config()
            return jsonify(updated_config.to_dict())

        except ValueError as e:
            app.logger.warning(f"Validation error updating global config: {str(e)}")
            return jsonify({'error': 'Validation error', 'message': str(e)}), 400
        except PermissionError:
            app.logger.error("Permission denied updating global DHCP configuration")
            return jsonify({'error': 'Permission denied writing DHCP configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to update global DHCP configuration: {str(e)}")
            return jsonify({'error': 'Failed to update global configuration', 'message': str(e)}), 500

    # App configuration endpoints
    @app.route(f"{app.config['API_PREFIX']}/app-config", methods=['GET'])
    @require_auth
    def get_app_config():
        """Get application configuration with sensitive values masked"""
        try:
            config = config_manager.read_config()
            masked_config = config_manager.mask_sensitive_values(config)
            app.logger.debug(f"Retrieved app configuration ({len(masked_config)} settings)")
            return jsonify(masked_config)
        except FileNotFoundError as e:
            app.logger.error(f"App configuration file not found: {str(e)}")
            return jsonify({'error': 'Configuration file not found', 'message': str(e)}), 404
        except PermissionError:
            app.logger.error("Permission denied accessing app configuration")
            return jsonify({'error': 'Permission denied accessing application configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to read app configuration: {str(e)}")
            return jsonify({'error': 'Failed to read application configuration', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/app-config/schema", methods=['GET'])
    @require_auth
    def get_app_config_schema():
        """Get configuration schema for frontend form generation"""
        try:
            schema = config_manager.get_schema()
            app.logger.debug("Retrieved app configuration schema")
            return jsonify(schema)
        except Exception as e:
            app.logger.error(f"Failed to read app configuration schema: {str(e)}")
            return jsonify({'error': 'Failed to read configuration schema', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/app-config", methods=['PUT'])
    @require_auth
    def update_app_config():
        """Update application configuration"""
        try:
            data = request.get_json()
            if not data:
                app.logger.warning("Update app config request with no JSON data")
                return jsonify({'error': 'No JSON data provided'}), 400

            # Read current config to preserve read-only fields
            current_config = config_manager.read_config()
            properties = config_manager.get_schema().get('properties', {})

            # Filter out read-only fields from the update
            updated_config = current_config.copy()
            modified_fields = []
            for key, value in data.items():
                if key in properties:
                    # Skip read-only fields
                    if properties[key].get('readOnly'):
                        continue
                    updated_config[key] = value
                    modified_fields.append(key)

            # Validate before writing
            errors = config_manager.validate_config(updated_config)
            if errors:
                app.logger.warning(f"App config validation failed: {'; '.join(errors)}")
                return jsonify({'error': 'Validation failed', 'message': '; '.join(errors)}), 400

            # Write configuration
            config_manager.write_config(updated_config)
            app.logger.info(f"Updated app configuration ({len(modified_fields)} fields: {', '.join(modified_fields)})")

            # Return updated config with masked values
            final_config = config_manager.read_config()
            masked_config = config_manager.mask_sensitive_values(final_config)
            return jsonify(masked_config)

        except ValueError as e:
            app.logger.warning(f"Validation error updating app config: {str(e)}")
            return jsonify({'error': 'Validation error', 'message': str(e)}), 400
        except PermissionError:
            app.logger.error("Permission denied updating app configuration")
            return jsonify({'error': 'Permission denied writing application configuration'}), 403
        except Exception as e:
            app.logger.error(f"Failed to update app configuration: {str(e)}")
            return jsonify({'error': 'Failed to update application configuration', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/tls/certificate-info", methods=['GET'])
    @require_auth
    def get_tls_certificate_info():
        """Get TLS certificate information"""
        try:
            cert_path = app.config.get('TLS_CERTIFICATE_PATH')
            app.logger.debug(f"Attempting to get certificate info for: {cert_path}")
            if not cert_path:
                app.logger.warning("TLS certificate path not configured")
                return jsonify({'error': 'TLS certificate path not configured'}), 400

            cert_info = get_certificate_info(cert_path)
            app.logger.debug(f"Retrieved TLS certificate info: {cert_path}")
            return jsonify(cert_info.to_dict())


        except FileNotFoundError as e:
            app.logger.warning(f"TLS certificate file not found: {str(e)}")
            return jsonify({'error': 'Certificate file not found', 'message': str(e)}), 404
        except PermissionError as e:
            app.logger.error(f"Permission denied reading TLS certificate: {str(e)}")
            return jsonify({'error': 'Permission denied', 'message': str(e)}), 403
        except ValueError as e:
            app.logger.warning(f"Invalid TLS certificate: {str(e)}")
            return jsonify({'error': 'Invalid certificate', 'message': str(e)}), 400
        except Exception as e:
            app.logger.error(f"Failed to get TLS certificate info: {str(e)}")
            return jsonify({'error': 'Failed to get certificate information', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/tls/validate-certificate", methods=['POST'])
    @require_auth
    def validate_tls_certificate():
        """Validate TLS certificate file"""
        try:
            data = request.get_json()
            cert_path = data.get('cert_path') if data else None

            # Use config value if not provided
            if not cert_path:
                cert_path = app.config.get('TLS_CERTIFICATE_PATH')

            if not cert_path:
                app.logger.warning("TLS certificate path not provided")
                return jsonify({'error': 'Certificate path required'}), 400

            is_valid, message = validate_certificate_file(cert_path)
            app.logger.info(f"TLS certificate validation: {message}")

            return jsonify({
                'valid': is_valid,
                'message': message
            })

        except Exception as e:
            app.logger.error(f"Failed to validate TLS certificate: {str(e)}")
            return jsonify({'error': 'Failed to validate certificate', 'message': str(e)}), 500

    return app


def main():
    """Run the application"""
    app = create_app()

    # Run the development server
    if app.config['DEBUG']:
        app.run(host='0.0.0.0', port=5000, debug=True)
    else:
        # Production should use a proper WSGI server like gunicorn
        app.run(host='0.0.0.0', port=5000)


if __name__ == '__main__':
    main()