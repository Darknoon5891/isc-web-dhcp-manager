"""
DHCP Configuration Parser
Handles parsing and modification of ISC DHCP Server configuration files
"""

import re
import os
import shutil
import tempfile
from datetime import datetime
from typing import List, Dict, Optional


class DHCPHost:
    """Represents a DHCP host reservation"""
    def __init__(self, hostname: str, mac: str, ip: str):
        self.hostname = hostname
        self.mac = mac.upper()
        self.ip = ip
    
    def to_dict(self) -> Dict[str, str]:
        return {
            'hostname': self.hostname,
            'mac': self.mac,
            'ip': self.ip
        }
    
    def to_dhcp_config(self) -> str:
        """Convert to DHCP configuration format"""
        return f"""host {self.hostname} {{
    hardware ethernet {self.mac};
    fixed-address {self.ip};
}}"""


class DHCPParser:
    """Parser for ISC DHCP Server configuration files"""
    
    def __init__(self, config_path: str = "/etc/dhcp/dhcpd.conf"):
        self.config_path = config_path
        self.backup_dir = "/etc/dhcp/backups"
    
    def validate_mac_address(self, mac: str) -> bool:
        """Validate MAC address format"""
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(pattern, mac))
    
    def validate_ip_address(self, ip: str) -> bool:
        """Validate IP address format"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    def validate_hostname(self, hostname: str) -> bool:
        """Validate hostname format"""
        pattern = r'^[a-zA-Z0-9-_]+$'
        return bool(re.match(pattern, hostname)) and len(hostname) > 0
    
    def create_backup(self) -> str:
        """Create a backup of the current configuration"""
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"dhcpd.conf.backup_{timestamp}"
        backup_path = os.path.join(self.backup_dir, backup_filename)
        
        if os.path.exists(self.config_path):
            shutil.copy2(self.config_path, backup_path)
        
        return backup_path
    
    def read_config(self) -> str:
        """Read the current DHCP configuration"""
        try:
            with open(self.config_path, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return ""
        except PermissionError:
            raise PermissionError(f"Permission denied reading {self.config_path}")
    
    def write_config(self, content: str) -> None:
        """Write new configuration content atomically"""
        try:
            # Get the directory and filename
            config_dir = os.path.dirname(self.config_path)
            config_file = os.path.basename(self.config_path)

            # Create temporary file in the same directory for atomic rename
            # Using same directory ensures we're on the same filesystem
            fd, temp_path = tempfile.mkstemp(
                dir=config_dir,
                prefix=f'.{config_file}.',
                suffix='.tmp',
                text=True
            )

            try:
                # Write to temporary file
                with os.fdopen(fd, 'w') as f:
                    f.write(content)
                    # Sync to disk before closing
                    f.flush()
                    os.fsync(f.fileno())

                # Get original file permissions if it exists
                if os.path.exists(self.config_path):
                    stat_info = os.stat(self.config_path)
                    os.chmod(temp_path, stat_info.st_mode)
                    try:
                        os.chown(temp_path, stat_info.st_uid, stat_info.st_gid)
                    except (PermissionError, OSError):
                        # chown may fail if not running as root, that's ok
                        pass

                # Atomic rename (overwrites existing file)
                os.replace(temp_path, self.config_path)

            except Exception as e:
                # Clean up temp file on error
                if os.path.exists(temp_path):
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass
                raise

        except PermissionError:
            raise PermissionError(f"Permission denied writing to {self.config_path}")
        except Exception as e:
            raise IOError(f"Failed to write config file: {str(e)}")
    
    def parse_hosts(self) -> List[DHCPHost]:
        """Parse all host declarations from the configuration"""
        content = self.read_config()
        hosts = []

        # Split content into reasonable chunks to prevent ReDoS
        # Process line by line or in smaller blocks
        lines = content.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Look for host declaration start
            host_match = re.match(r'host\s+(\S+)\s*\{', line)
            if host_match:
                hostname = host_match.group(1)
                mac = None
                ip = None

                # Parse the host block (limit to 100 lines to prevent abuse)
                block_end = min(i + 100, len(lines))
                brace_count = 1
                j = i + 1

                while j < block_end and brace_count > 0:
                    block_line = lines[j].strip()

                    # Count braces
                    brace_count += block_line.count('{') - block_line.count('}')

                    # Extract MAC address
                    if not mac:
                        mac_match = re.match(r'hardware\s+ethernet\s+([0-9A-Fa-f:]+)\s*;', block_line)
                        if mac_match:
                            mac = mac_match.group(1)

                    # Extract IP address
                    if not ip:
                        ip_match = re.match(r'fixed-address\s+([0-9.]+)\s*;', block_line)
                        if ip_match:
                            ip = ip_match.group(1)

                    j += 1

                    if brace_count == 0:
                        break

                # Only add hosts with both MAC and IP
                if mac and ip:
                    mac = mac.replace(':', ':').upper()  # Normalize MAC format
                    hosts.append(DHCPHost(hostname, mac, ip))

                i = j
            else:
                i += 1

        return hosts
    
    def get_host(self, hostname: str) -> Optional[DHCPHost]:
        """Get a specific host by hostname"""
        hosts = self.parse_hosts()
        for host in hosts:
            if host.hostname == hostname:
                return host
        return None
    
    def add_host(self, hostname: str, mac: str, ip: str) -> bool:
        """Add a new host reservation"""
        # Validate inputs
        if not self.validate_hostname(hostname):
            raise ValueError(f"Invalid hostname: {hostname}")
        if not self.validate_mac_address(mac):
            raise ValueError(f"Invalid MAC address: {mac}")
        if not self.validate_ip_address(ip):
            raise ValueError(f"Invalid IP address: {ip}")
        
        # Check if host already exists
        if self.get_host(hostname):
            raise ValueError(f"Host {hostname} already exists")
        
        # Check for duplicate MAC or IP
        hosts = self.parse_hosts()
        for host in hosts:
            if host.mac.upper() == mac.upper():
                raise ValueError(f"MAC address {mac} already in use by {host.hostname}")
            if host.ip == ip:
                raise ValueError(f"IP address {ip} already in use by {host.hostname}")
        
        # Create backup before modification
        self.create_backup()
        
        # Read current content
        content = self.read_config()
        
        # Create new host entry
        new_host = DHCPHost(hostname, mac, ip)
        host_config = new_host.to_dhcp_config()
        
        # Find a good place to insert the new host
        # Look for existing host declarations or add at the end
        if "host " in content:
            # Find the last host declaration using line-based parsing
            lines = content.split('\n')
            last_host_line = -1

            for i, line in enumerate(lines):
                if re.match(r'host\s+\S+\s*\{', line.strip()):
                    # Track the end of this host block
                    brace_count = line.count('{') - line.count('}')
                    j = i + 1
                    while j < len(lines) and brace_count > 0:
                        brace_count += lines[j].count('{') - lines[j].count('}')
                        j += 1
                    last_host_line = j - 1

            if last_host_line >= 0:
                # Insert after the last host
                lines.insert(last_host_line + 1, "")
                lines.insert(last_host_line + 2, host_config)
                content = '\n'.join(lines)
            else:
                content += "\n\n" + host_config + "\n"
        else:
            # No existing hosts, add at the end
            content += "\n\n# Static host reservations\n" + host_config + "\n"
        
        # Write updated content
        self.write_config(content)
        return True
    
    def update_host(self, hostname: str, new_mac: str = None, new_ip: str = None) -> bool:
        """Update an existing host reservation"""
        host = self.get_host(hostname)
        if not host:
            raise ValueError(f"Host {hostname} not found")
        
        # Validate new values if provided
        if new_mac and not self.validate_mac_address(new_mac):
            raise ValueError(f"Invalid MAC address: {new_mac}")
        if new_ip and not self.validate_ip_address(new_ip):
            raise ValueError(f"Invalid IP address: {new_ip}")
        
        # Check for conflicts with other hosts
        hosts = self.parse_hosts()
        for other_host in hosts:
            if other_host.hostname != hostname:
                if new_mac and other_host.mac.upper() == new_mac.upper():
                    raise ValueError(f"MAC address {new_mac} already in use by {other_host.hostname}")
                if new_ip and other_host.ip == new_ip:
                    raise ValueError(f"IP address {new_ip} already in use by {other_host.hostname}")
        
        # Create backup before modification
        self.create_backup()
        
        # Update the host
        if new_mac:
            host.mac = new_mac.upper()
        if new_ip:
            host.ip = new_ip
        
        # Replace the host in the configuration
        return self._replace_host_in_config(hostname, host)
    
    def delete_host(self, hostname: str) -> bool:
        """Delete a host reservation"""
        host = self.get_host(hostname)
        if not host:
            raise ValueError(f"Host {hostname} not found")

        # Create backup before modification
        self.create_backup()

        # Read current content
        content = self.read_config()

        # Use line-based parsing instead of complex regex
        lines = content.split('\n')
        new_lines = []
        i = 0
        deleted = False

        while i < len(lines):
            line = lines[i]

            # Check if this is the start of our target host
            host_start = re.match(rf'host\s+{re.escape(hostname)}\s*\{{', line.strip())
            if host_start and not deleted:
                # Skip this host block
                brace_count = line.count('{') - line.count('}')
                i += 1

                # Skip until we close the block
                while i < len(lines) and brace_count > 0:
                    brace_count += lines[i].count('{') - lines[i].count('}')
                    i += 1

                deleted = True
            else:
                new_lines.append(line)
                i += 1

        new_content = '\n'.join(new_lines)

        # Clean up any extra whitespace
        new_content = re.sub(r'\n\s*\n\s*\n', '\n\n', new_content)

        self.write_config(new_content)
        return True
    
    def _replace_host_in_config(self, hostname: str, new_host: DHCPHost) -> bool:
        """Replace a host declaration in the configuration"""
        content = self.read_config()

        # Use a simpler, non-backtracking approach
        # Find the host block by line scanning instead of complex regex
        lines = content.split('\n')
        new_lines = []
        i = 0
        replaced = False

        while i < len(lines):
            line = lines[i]

            # Check if this is the start of our target host
            host_start = re.match(rf'host\s+{re.escape(hostname)}\s*\{{', line.strip())
            if host_start and not replaced:
                # Skip this host block
                brace_count = line.count('{') - line.count('}')
                i += 1

                # Skip until we close the block
                while i < len(lines) and brace_count > 0:
                    brace_count += lines[i].count('{') - lines[i].count('}')
                    i += 1

                # Insert the new host config
                new_lines.append(new_host.to_dhcp_config())
                replaced = True
            else:
                new_lines.append(line)
                i += 1

        new_content = '\n'.join(new_lines)
        self.write_config(new_content)
        return True
    
    def validate_config(self) -> tuple[bool, str]:
        """Validate the current DHCP configuration"""
        try:
            # Basic syntax validation
            content = self.read_config()
            
            # Check for balanced braces
            brace_count = content.count('{') - content.count('}')
            if brace_count != 0:
                return False, f"Unbalanced braces in configuration (difference: {brace_count})"
            
            # Check for duplicate hostnames
            hosts = self.parse_hosts()
            hostnames = [host.hostname for host in hosts]
            if len(hostnames) != len(set(hostnames)):
                return False, "Duplicate hostnames found in configuration"
            
            # Check for duplicate MAC addresses
            macs = [host.mac for host in hosts]
            if len(macs) != len(set(macs)):
                return False, "Duplicate MAC addresses found in configuration"
            
            # Check for duplicate IP addresses
            ips = [host.ip for host in hosts]
            if len(ips) != len(set(ips)):
                return False, "Duplicate IP addresses found in configuration"
            
            return True, "Configuration is valid"
            
        except Exception as e:
            return False, f"Configuration validation error: {str(e)}"