"""
ISC Web DHCP Configuration Manager Flask Application
Provides REST API for managing ISC DHCP Server configuration
"""

import os
import subprocess
import socket
from flask import Flask, request, jsonify
from flask_cors import CORS
from dhcp_parser import DHCPParser, DHCPHost, DHCPSubnet, DHCPZone, DHCPGlobalConfig
from config import get_config


def create_app():
    """Application factory"""
    app = Flask(__name__)
    
    # Load configuration
    config_class = get_config()
    app.config.from_object(config_class)
    
    # Initialize CORS
    CORS(app, origins=app.config['CORS_ORIGINS'])
    
    # Initialize DHCP parser
    dhcp_parser = DHCPParser(app.config['DHCP_CONFIG_PATH'])
    
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({'error': 'Bad request', 'message': str(error)}), 400
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found', 'message': str(error)}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal server error', 'message': str(error)}), 500
    
    @app.route('/')
    @app.route(f"{app.config['API_PREFIX']}/")
    def index():
        """Health check endpoint"""
        return jsonify({
            'status': 'running',
            'service': 'ISC Web DHCP Configuration Manager',
            'version': '1.0.0'
        })

    @app.route(f"{app.config['API_PREFIX']}/system/hostname", methods=['GET'])
    def get_system_hostname():
        """Get the server hostname"""
        try:
            hostname = socket.gethostname()
            return jsonify({'hostname': hostname})
        except Exception as e:
            return jsonify({'error': 'Failed to get hostname', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/hosts", methods=['GET'])
    def get_hosts():
        """Get all DHCP host reservations"""
        try:
            hosts = dhcp_parser.parse_hosts()
            return jsonify([host.to_dict() for host in hosts])
        except PermissionError:
            return jsonify({'error': 'Permission denied accessing DHCP configuration'}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to read hosts', 'message': str(e)}), 500
    
    @app.route(f"{app.config['API_PREFIX']}/hosts/<hostname>", methods=['GET'])
    def get_host(hostname):
        """Get a specific host reservation"""
        try:
            host = dhcp_parser.get_host(hostname)
            if host:
                return jsonify(host.to_dict())
            return jsonify({'error': 'Host not found'}), 404
        except PermissionError:
            return jsonify({'error': 'Permission denied accessing DHCP configuration'}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to read host', 'message': str(e)}), 500
    
    @app.route(f"{app.config['API_PREFIX']}/hosts", methods=['POST'])
    def add_host():
        """Add a new host reservation"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No JSON data provided'}), 400
            
            hostname = data.get('hostname')
            mac = data.get('mac')
            ip = data.get('ip')
            
            if not all([hostname, mac, ip]):
                return jsonify({'error': 'hostname, mac, and ip are required'}), 400
            
            # Validate input lengths
            if len(hostname) > app.config['MAX_HOSTNAME_LENGTH']:
                return jsonify({'error': f'Hostname too long (max {app.config["MAX_HOSTNAME_LENGTH"]} characters)'}), 400
            
            dhcp_parser.add_host(hostname, mac, ip)
            
            # Return the created host
            new_host = dhcp_parser.get_host(hostname)
            return jsonify(new_host.to_dict()), 201
            
        except ValueError as e:
            return jsonify({'error': 'Validation error', 'message': str(e)}), 400
        except PermissionError:
            return jsonify({'error': 'Permission denied modifying DHCP configuration',}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to add host', 'message': str(e)}), 500
    
    @app.route(f"{app.config['API_PREFIX']}/hosts/<hostname>", methods=['PUT'])
    def update_host(hostname):
        """Update an existing host reservation"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No JSON data provided'}), 400
            
            new_mac = data.get('mac')
            new_ip = data.get('ip')
            
            if not new_mac and not new_ip:
                return jsonify({'error': 'At least one of mac or ip must be provided'}), 400
            
            dhcp_parser.update_host(hostname, new_mac, new_ip)
            
            # Return the updated host
            updated_host = dhcp_parser.get_host(hostname)
            return jsonify(updated_host.to_dict())
            
        except ValueError as e:
            return jsonify({'error': 'Validation error', 'message': str(e)}), 400
        except PermissionError:
            return jsonify({'error': 'Permission denied modifying DHCP configuration'}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to update host', 'message': str(e)}), 500
    
    @app.route(f"{app.config['API_PREFIX']}/hosts/<hostname>", methods=['DELETE'])
    def delete_host(hostname):
        """Delete a host reservation"""
        try:
            dhcp_parser.delete_host(hostname)
            return jsonify({'message': f'Host {hostname} deleted successfully'})
            
        except ValueError as e:
            return jsonify({'error': 'Validation error', 'message': str(e)}), 404
        except PermissionError:
            return jsonify({'error': 'Permission denied modifying DHCP configuration',}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to delete host', 'message': str(e)}), 500
    
    @app.route(f"{app.config['API_PREFIX']}/config", methods=['GET'])
    def get_config_content():
        """Get the raw DHCP configuration content"""
        try:
            content = dhcp_parser.read_config()
            return jsonify({'config': content})
        except PermissionError:
            return jsonify({'error': 'Permission denied accessing DHCP configuration'}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to read configuration', 'message': str(e)}), 500
    
    @app.route(f"{app.config['API_PREFIX']}/validate", methods=['POST'])
    def validate_config():
        """Validate the current DHCP configuration"""
        try:
            is_valid, message = dhcp_parser.validate_config()
            return jsonify({
                'valid': is_valid,
                'message': message
            })
        except Exception as e:
            return jsonify({'error': 'Failed to validate configuration', 'message': str(e)}), 500
    
    @app.route(f"{app.config['API_PREFIX']}/restart", methods=['POST'])
    def restart_dhcp_service():
        """Restart the DHCP service"""
        if not app.config['ALLOW_SERVICE_RESTART']:
            return jsonify({'error': 'Service restart is disabled'}), 403
        
        try:
            # First validate the configuration
            is_valid, validation_message = dhcp_parser.validate_config()
            if not is_valid:
                return jsonify({
                    'error': 'Configuration validation failed',
                    'message': validation_message
                }), 400
            
            # Restart the service
            service_name = app.config['DHCP_SERVICE_NAME']
            
            # Use systemctl to restart the service (requires sudo)
            result = subprocess.run(
                ['/usr/bin/sudo', '/bin/systemctl', 'restart', service_name],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                # Check if service is running
                # Note: is-active returns non-zero if service is not active - this is normal
                status_result = subprocess.run(
                    ['/bin/systemctl', 'is-active', service_name],
                    capture_output=True,
                    text=True
                )

                service_status = status_result.stdout.strip()

                if service_status == 'active':
                    return jsonify({
                        'message': f'DHCP service {service_name} restarted successfully',
                        'status': 'active'
                    })
                else:
                    error_msg = f'Service restart failed - service is {service_status}'
                    if result.stderr:
                        error_msg += f'\n{result.stderr.strip()}'
                    return jsonify({
                        'error': error_msg,
                        'message': error_msg,
                        'status': service_status
                    }), 500
            else:
                error_msg = result.stderr.strip() if result.stderr else f'Failed to restart DHCP service {service_name}'
                return jsonify({
                    'error': error_msg,
                    'message': error_msg
                }), 500

        except subprocess.TimeoutExpired:
            return jsonify({'error': 'Service restart timed out', 'message': 'Service restart timed out'}), 500
        except PermissionError:
            return jsonify({'error': 'Permission denied - sudo access required', 'message': 'Permission denied - sudo access required'}), 403
        except FileNotFoundError as e:
            return jsonify({'error': f'Command not found: {e.filename}', 'message': f'Command not found: {e.filename}'}), 500
        except Exception as e:
            return jsonify({'error': 'Failed to restart service', 'message': str(e)}), 500
    
    @app.route(f"{app.config['API_PREFIX']}/service/status", methods=['GET'])
    def get_service_status():
        """Get the current status of the DHCP service"""
        try:
            service_name = app.config['DHCP_SERVICE_NAME']

            # Get service status (polkit handles authentication)
            # Note: is-active returns non-zero if service is not active - this is normal
            result = subprocess.run(
                ['/bin/systemctl', 'is-active', service_name],
                capture_output=True,
                text=True
            )

            status = result.stdout.strip()

            # Get more detailed status
            # Note: status returns non-zero if service is not active - this is normal
            detail_result = subprocess.run(
                ['/bin/systemctl', 'status', service_name, '--no-pager', '-l'],
                capture_output=True,
                text=True
            )

            return jsonify({
                'service': service_name,
                'status': status,
                'active': status == 'active',
                'details': detail_result.stdout
            })

        except FileNotFoundError:
            return jsonify({'error': 'systemctl command not found', 'message': 'systemctl not available at /bin/systemctl'}), 500
        except Exception as e:
            return jsonify({'error': 'Failed to get service status', 'message': str(e)}), 500
    
    @app.route(f"{app.config['API_PREFIX']}/backups", methods=['GET'])
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

            return jsonify(backups)

        except Exception as e:
            return jsonify({'error': 'Failed to list backups', 'message': str(e)}), 500

    # Subnet management endpoints
    @app.route(f"{app.config['API_PREFIX']}/subnets", methods=['GET'])
    def get_subnets():
        """Get all subnet declarations"""
        try:
            subnets = dhcp_parser.parse_subnets()
            return jsonify([subnet.to_dict() for subnet in subnets])
        except PermissionError:
            return jsonify({'error': 'Permission denied accessing DHCP configuration'}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to read subnets', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/subnets/<network>", methods=['GET'])
    def get_subnet(network):
        """Get a specific subnet"""
        try:
            subnet = dhcp_parser.get_subnet(network)
            if subnet:
                return jsonify(subnet.to_dict())
            return jsonify({'error': 'Subnet not found'}), 404
        except PermissionError:
            return jsonify({'error': 'Permission denied accessing DHCP configuration'}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to read subnet', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/subnets", methods=['POST'])
    def add_subnet():
        """Add a new subnet"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No JSON data provided'}), 400

            network = data.get('network')
            netmask = data.get('netmask')
            range_start = data.get('range_start')
            range_end = data.get('range_end')
            options = data.get('options', {})

            if not all([network, netmask]):
                return jsonify({'error': 'network and netmask are required'}), 400

            dhcp_parser.add_subnet(network, netmask, range_start, range_end, options)

            # Return the created subnet
            new_subnet = dhcp_parser.get_subnet(network)
            return jsonify(new_subnet.to_dict()), 201

        except ValueError as e:
            return jsonify({'error': 'Validation error', 'message': str(e)}), 400
        except PermissionError:
            return jsonify({'error': 'Permission denied writing DHCP configuration'}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to add subnet', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/subnets/<network>", methods=['PUT'])
    def update_subnet(network):
        """Update an existing subnet"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No JSON data provided'}), 400

            new_netmask = data.get('netmask')
            new_range_start = data.get('range_start')
            new_range_end = data.get('range_end')
            new_options = data.get('options')

            dhcp_parser.update_subnet(network, new_netmask, new_range_start, new_range_end, new_options)

            # Return the updated subnet
            updated_subnet = dhcp_parser.get_subnet(network)
            return jsonify(updated_subnet.to_dict())

        except ValueError as e:
            return jsonify({'error': 'Validation error', 'message': str(e)}), 400
        except PermissionError:
            return jsonify({'error': 'Permission denied writing DHCP configuration'}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to update subnet', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/subnets/<network>", methods=['DELETE'])
    def delete_subnet(network):
        """Delete a subnet"""
        try:
            dhcp_parser.delete_subnet(network)
            return jsonify({'message': f'Subnet {network} deleted successfully'})

        except ValueError as e:
            return jsonify({'error': 'Validation error', 'message': str(e)}), 404
        except PermissionError:
            return jsonify({'error': 'Permission denied writing DHCP configuration'}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to delete subnet', 'message': str(e)}), 500

    # Zone management endpoints
    @app.route(f"{app.config['API_PREFIX']}/zones", methods=['GET'])
    def get_zones():
        """Get all zone declarations"""
        try:
            zones = dhcp_parser.parse_zones()
            return jsonify([zone.to_dict() for zone in zones])
        except PermissionError:
            return jsonify({'error': 'Permission denied accessing DHCP configuration'}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to read zones', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/zones/<zone_name>", methods=['GET'])
    def get_zone(zone_name):
        """Get a specific zone"""
        try:
            zone = dhcp_parser.get_zone(zone_name)
            if zone:
                return jsonify(zone.to_dict())
            return jsonify({'error': 'Zone not found'}), 404
        except PermissionError:
            return jsonify({'error': 'Permission denied accessing DHCP configuration'}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to read zone', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/zones", methods=['POST'])
    def add_zone():
        """Add a new zone"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No JSON data provided'}), 400

            zone_name = data.get('zone_name')
            primary = data.get('primary')
            key_name = data.get('key_name')
            secondary = data.get('secondary', [])

            if not all([zone_name, primary]):
                return jsonify({'error': 'zone_name and primary are required'}), 400

            dhcp_parser.add_zone(zone_name, primary, key_name, secondary)

            # Return the created zone
            new_zone = dhcp_parser.get_zone(zone_name)
            return jsonify(new_zone.to_dict()), 201

        except ValueError as e:
            return jsonify({'error': 'Validation error', 'message': str(e)}), 400
        except PermissionError:
            return jsonify({'error': 'Permission denied writing DHCP configuration'}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to add zone', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/zones/<zone_name>", methods=['PUT'])
    def update_zone(zone_name):
        """Update an existing zone"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No JSON data provided'}), 400

            new_primary = data.get('primary')
            new_key_name = data.get('key_name')
            new_secondary = data.get('secondary')

            dhcp_parser.update_zone(zone_name, new_primary, new_key_name, new_secondary)

            # Return the updated zone
            updated_zone = dhcp_parser.get_zone(zone_name)
            return jsonify(updated_zone.to_dict())

        except ValueError as e:
            return jsonify({'error': 'Validation error', 'message': str(e)}), 400
        except PermissionError:
            return jsonify({'error': 'Permission denied writing DHCP configuration'}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to update zone', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/zones/<zone_name>", methods=['DELETE'])
    def delete_zone(zone_name):
        """Delete a zone"""
        try:
            dhcp_parser.delete_zone(zone_name)
            return jsonify({'message': f'Zone {zone_name} deleted successfully'})

        except ValueError as e:
            return jsonify({'error': 'Validation error', 'message': str(e)}), 404
        except PermissionError:
            return jsonify({'error': 'Permission denied writing DHCP configuration'}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to delete zone', 'message': str(e)}), 500

    # Global configuration endpoints
    @app.route(f"{app.config['API_PREFIX']}/global-config", methods=['GET'])
    def get_global_config():
        """Get global DHCP configuration settings"""
        try:
            config = dhcp_parser.parse_global_config()
            return jsonify(config.to_dict())
        except PermissionError:
            return jsonify({'error': 'Permission denied accessing DHCP configuration'}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to read global configuration', 'message': str(e)}), 500

    @app.route(f"{app.config['API_PREFIX']}/global-config", methods=['PUT'])
    def update_global_config():
        """Update global DHCP configuration settings"""
        try:
            data = request.get_json()
            if not data:
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
            updated_config = dhcp_parser.parse_global_config()
            return jsonify(updated_config.to_dict())

        except ValueError as e:
            return jsonify({'error': 'Validation error', 'message': str(e)}), 400
        except PermissionError:
            return jsonify({'error': 'Permission denied writing DHCP configuration'}), 403
        except Exception as e:
            return jsonify({'error': 'Failed to update global configuration', 'message': str(e)}), 500

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