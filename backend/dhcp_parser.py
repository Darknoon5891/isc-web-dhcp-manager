"""
DHCP Configuration Parser
Handles parsing and modification of ISC DHCP Server configuration files
"""

import re
import os
import shutil
import tempfile
import logging
from datetime import datetime
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


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


class DHCPSubnet:
    """Represents a DHCP subnet declaration"""
    def __init__(self, network: str, netmask: str, range_start: str = None,
                 range_end: str = None, options: Dict[str, str] = None):
        self.network = network
        self.netmask = netmask
        self.range_start = range_start
        self.range_end = range_end
        self.options = options or {}

    def to_dict(self) -> Dict:
        return {
            'network': self.network,
            'netmask': self.netmask,
            'range_start': self.range_start,
            'range_end': self.range_end,
            'options': self.options
        }

    def to_dhcp_config(self) -> str:
        """Convert to DHCP configuration format"""
        lines = [f"subnet {self.network} netmask {self.netmask} {{"]

        # Add range if specified
        if self.range_start and self.range_end:
            lines.append(f"    range {self.range_start} {self.range_end};")

        # Add options
        for key, value in sorted(self.options.items()):
            lines.append(f"    option {key} {value};")

        lines.append("}")
        return '\n'.join(lines)


class DHCPZone:
    """Represents a DHCP zone declaration for DNS updates"""
    def __init__(self, zone_name: str, primary: str, key_name: str = None, secondary: List[str] = None):
        self.zone_name = zone_name
        self.primary = primary
        self.key_name = key_name
        self.secondary = secondary or []

    def to_dict(self) -> Dict:
        return {
            'zone_name': self.zone_name,
            'primary': self.primary,
            'key_name': self.key_name,
            'secondary': self.secondary
        }

    def to_dhcp_config(self) -> str:
        """Convert to DHCP configuration format"""
        # Zone names must end with a dot in DHCP config
        zone_name_with_dot = self.zone_name if self.zone_name.endswith('.') else f"{self.zone_name}."
        lines = [f'zone "{zone_name_with_dot}" {{']

        # Add primary server
        lines.append(f"    primary {self.primary};")

        # Add key if specified
        if self.key_name:
            lines.append(f"    key {self.key_name};")

        # Add secondary servers if specified
        for sec in self.secondary:
            lines.append(f"    secondary {sec};")

        lines.append("}")
        return '\n'.join(lines)


class DHCPGlobalConfig:
    """Represents DHCP global configuration settings"""
    def __init__(self,
                 default_lease_time: int = 600,
                 max_lease_time: int = 7200,
                 authoritative: bool = False,
                 log_facility: str = None,
                 domain_name: str = None,
                 domain_name_servers: str = None,
                 ntp_servers: str = None,
                 time_offset: int = None,
                 ddns_update_style: str = 'none',
                 ping_check: bool = False,
                 ping_timeout: int = None):
        self.default_lease_time = default_lease_time
        self.max_lease_time = max_lease_time
        self.authoritative = authoritative
        self.log_facility = log_facility
        self.domain_name = domain_name
        self.domain_name_servers = domain_name_servers
        self.ntp_servers = ntp_servers
        self.time_offset = time_offset
        self.ddns_update_style = ddns_update_style
        self.ping_check = ping_check
        self.ping_timeout = ping_timeout

    def to_dict(self) -> Dict:
        return {
            'default_lease_time': self.default_lease_time,
            'max_lease_time': self.max_lease_time,
            'authoritative': self.authoritative,
            'log_facility': self.log_facility,
            'domain_name': self.domain_name,
            'domain_name_servers': self.domain_name_servers,
            'ntp_servers': self.ntp_servers,
            'time_offset': self.time_offset,
            'ddns_update_style': self.ddns_update_style,
            'ping_check': self.ping_check,
            'ping_timeout': self.ping_timeout
        }

    def to_dhcp_config_lines(self) -> List[str]:
        """Convert to DHCP configuration lines"""
        lines = []
        lines.append("# Global Configuration")
        lines.append(f"default-lease-time {self.default_lease_time};")
        lines.append(f"max-lease-time {self.max_lease_time};")

        if self.authoritative:
            lines.append("authoritative;")

        if self.log_facility:
            lines.append(f"log-facility {self.log_facility};")

        if self.ddns_update_style:
            lines.append(f"ddns-update-style {self.ddns_update_style};")

        if self.ping_check:
            lines.append("ping-check true;")
            if self.ping_timeout:
                lines.append(f"ping-timeout {self.ping_timeout};")

        # Global options
        if self.domain_name:
            lines.append(f'option domain-name "{self.domain_name}";')

        if self.domain_name_servers:
            lines.append(f"option domain-name-servers {self.domain_name_servers};")

        if self.ntp_servers:
            lines.append(f"option ntp-servers {self.ntp_servers};")

        if self.time_offset is not None:
            lines.append(f"option time-offset {self.time_offset};")

        return lines


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
        """
        Validate hostname format (RFC 952/1123 compliant)
        - Total length: 1-253 characters
        - Each label: 1-63 characters
        - Labels must start/end with alphanumeric
        - Hyphens allowed in middle of labels
        - Supports FQDN with optional trailing dot
        """
        pattern = r'^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$'
        return bool(re.match(pattern, hostname))

    def validate_netmask(self, netmask: str) -> bool:
        """Validate netmask format"""
        if not self.validate_ip_address(netmask):
            return False
        # Check if it's a valid netmask (contiguous 1s followed by 0s in binary)
        try:
            parts = [int(p) for p in netmask.split('.')]
            binary = ''.join(format(p, '08b') for p in parts)
            # Valid netmask: all 1s followed by all 0s
            return binary.find('01') == -1 and '1' in binary
        except:
            return False

    def ip_in_subnet(self, ip: str, network: str, netmask: str) -> bool:
        """Check if an IP address is within a subnet"""
        try:
            ip_parts = [int(p) for p in ip.split('.')]
            net_parts = [int(p) for p in network.split('.')]
            mask_parts = [int(p) for p in netmask.split('.')]

            for i in range(4):
                if (ip_parts[i] & mask_parts[i]) != (net_parts[i] & mask_parts[i]):
                    return False
            return True
        except:
            return False

    def validate_zone_name(self, zone_name: str) -> bool:
        """Validate zone name format"""
        if not zone_name or len(zone_name) < 3:
            return False
        # Remove trailing dot if present for validation
        name = zone_name.rstrip('.')
        # Check for valid characters and structure
        pattern = r'^[a-zA-Z0-9.-]+$'
        return bool(re.match(pattern, name))

    def create_backup(self) -> str:
        """Create a backup of the current configuration"""
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"dhcpd.conf.backup_{timestamp}"
        backup_path = os.path.join(self.backup_dir, backup_filename)

        if os.path.exists(self.config_path):
            shutil.copy2(self.config_path, backup_path)
            logger.info(f"Created DHCP config backup: {backup_filename}")

        return backup_path
    
    def read_config(self) -> str:
        """Read the current DHCP configuration"""
        try:
            with open(self.config_path, 'r') as f:
                content = f.read()
                logger.debug(f"Read DHCP config file: {len(content)} bytes")
                return content
        except FileNotFoundError:
            logger.warning(f"DHCP config file not found: {self.config_path}")
            return ""
        except PermissionError:
            logger.error(f"Permission denied reading DHCP config: {self.config_path}")
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
                        # Preserve original ownership (UID and GID)
                        os.chown(temp_path, stat_info.st_uid, stat_info.st_gid)
                        logger.debug(f"Preserved DHCP config ownership: uid={stat_info.st_uid}, gid={stat_info.st_gid}")
                    except (PermissionError, OSError) as e:
                        # chown may fail if not running as root, that's ok
                        logger.warning(f"Failed to preserve ownership on DHCP config file (uid={stat_info.st_uid}, gid={stat_info.st_gid}): {str(e)}")
                        logger.warning("DHCP config file may have incorrect ownership - check permissions manually")

                # Atomic rename (overwrites existing file)
                os.replace(temp_path, self.config_path)
                logger.info(f"Wrote DHCP config file: {len(content)} bytes")

            except Exception as e:
                # Clean up temp file on error
                if os.path.exists(temp_path):
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass
                logger.error(f"Failed to write DHCP config atomically: {str(e)}")
                raise

        except PermissionError:
            logger.error(f"Permission denied writing to DHCP config: {self.config_path}")
            raise PermissionError(f"Permission denied writing to {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to write DHCP config file: {str(e)}")
            raise IOError(f"Failed to write config file: {str(e)}")
    
    def parse_hosts(self) -> List[DHCPHost]:
        """Parse all host declarations from the configuration"""
        content = self.read_config()
        hosts = []
        logger.debug("Parsing DHCP host declarations")

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

        logger.debug(f"Parsed {len(hosts)} DHCP host declarations")
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
        logger.info(f"Added DHCP host: {hostname} (MAC: {mac}, IP: {ip})")
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
        changes = []
        if new_mac:
            host.mac = new_mac.upper()
            changes.append(f"MAC: {new_mac}")
        if new_ip:
            host.ip = new_ip
            changes.append(f"IP: {new_ip}")

        # Replace the host in the configuration
        result = self._replace_host_in_config(hostname, host)
        logger.info(f"Updated DHCP host: {hostname} ({', '.join(changes)})")
        return result
    
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
        logger.info(f"Deleted DHCP host: {hostname}")
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
                logger.warning(f"DHCP config validation failed: Unbalanced braces ({brace_count})")
                return False, f"Unbalanced braces in configuration (difference: {brace_count})"

            # Check for duplicate hostnames
            hosts = self.parse_hosts()
            hostnames = [host.hostname for host in hosts]
            if len(hostnames) != len(set(hostnames)):
                logger.warning("DHCP config validation failed: Duplicate hostnames")
                return False, "Duplicate hostnames found in configuration"

            # Check for duplicate MAC addresses
            macs = [host.mac for host in hosts]
            if len(macs) != len(set(macs)):
                logger.warning("DHCP config validation failed: Duplicate MAC addresses")
                return False, "Duplicate MAC addresses found in configuration"

            # Check for duplicate IP addresses
            ips = [host.ip for host in hosts]
            if len(ips) != len(set(ips)):
                logger.warning("DHCP config validation failed: Duplicate IP addresses")
                return False, "Duplicate IP addresses found in configuration"

            logger.info("DHCP config validation passed")
            return True, "Configuration is valid"

        except Exception as e:
            logger.error(f"DHCP config validation error: {str(e)}")
            return False, f"Configuration validation error: {str(e)}"

    def parse_subnets(self) -> List[DHCPSubnet]:
        """Parse all subnet declarations from the configuration"""
        content = self.read_config()
        subnets = []
        logger.debug("Parsing DHCP subnet declarations")

        lines = content.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Look for subnet declaration start
            subnet_match = re.match(r'subnet\s+(\S+)\s+netmask\s+(\S+)\s*\{', line)
            if subnet_match:
                network = subnet_match.group(1)
                netmask = subnet_match.group(2)
                range_start = None
                range_end = None
                options = {}

                # Parse the subnet block (limit to 200 lines)
                block_end = min(i + 200, len(lines))
                brace_count = 1
                j = i + 1

                while j < block_end and brace_count > 0:
                    block_line = lines[j].strip()

                    # Count braces
                    brace_count += block_line.count('{') - block_line.count('}')

                    # Extract range
                    if not range_start:
                        range_match = re.match(r'range\s+([0-9.]+)\s+([0-9.]+)\s*;', block_line)
                        if range_match:
                            range_start = range_match.group(1)
                            range_end = range_match.group(2)

                    # Extract options
                    option_match = re.match(r'option\s+([a-z-]+)\s+(.+?)\s*;', block_line)
                    if option_match:
                        opt_name = option_match.group(1)
                        opt_value = option_match.group(2)
                        options[opt_name] = opt_value

                    j += 1

                    if brace_count == 0:
                        break

                subnets.append(DHCPSubnet(network, netmask, range_start, range_end, options))
                i = j
            else:
                i += 1

        logger.debug(f"Parsed {len(subnets)} DHCP subnet declarations")
        return subnets

    def get_subnet(self, network: str) -> Optional[DHCPSubnet]:
        """Get a specific subnet by network address"""
        subnets = self.parse_subnets()
        for subnet in subnets:
            if subnet.network == network:
                return subnet
        return None

    def add_subnet(self, network: str, netmask: str, range_start: str = None,
                   range_end: str = None, options: Dict[str, str] = None) -> bool:
        """Add a new subnet declaration"""
        # Validate inputs
        if not self.validate_ip_address(network):
            raise ValueError(f"Invalid network address: {network}")
        if not self.validate_netmask(netmask):
            raise ValueError(f"Invalid netmask: {netmask}")
        if range_start and not self.validate_ip_address(range_start):
            raise ValueError(f"Invalid range start IP: {range_start}")
        if range_end and not self.validate_ip_address(range_end):
            raise ValueError(f"Invalid range end IP: {range_end}")

        # Validate range is within subnet
        if range_start and not self.ip_in_subnet(range_start, network, netmask):
            raise ValueError(f"Range start {range_start} is not in subnet {network}/{netmask}")
        if range_end and not self.ip_in_subnet(range_end, network, netmask):
            raise ValueError(f"Range end {range_end} is not in subnet {network}/{netmask}")

        # Check if subnet already exists
        if self.get_subnet(network):
            raise ValueError(f"Subnet {network} already exists")

        # Check for overlapping subnets
        subnets = self.parse_subnets()
        for subnet in subnets:
            # Check if new subnet overlaps with existing
            if (self.ip_in_subnet(network, subnet.network, subnet.netmask) or
                self.ip_in_subnet(subnet.network, network, netmask)):
                raise ValueError(f"Subnet {network}/{netmask} overlaps with existing subnet {subnet.network}/{subnet.netmask}")

        # Create backup before modification
        self.create_backup()

        # Read current content
        content = self.read_config()

        # Create new subnet entry
        new_subnet = DHCPSubnet(network, netmask, range_start, range_end, options or {})
        subnet_config = new_subnet.to_dhcp_config()

        # Find good place to insert (after global options, before hosts)
        lines = content.split('\n')
        insert_pos = len(lines)

        # Look for first host declaration
        for i, line in enumerate(lines):
            if re.match(r'host\s+\S+\s*\{', line.strip()):
                insert_pos = i
                break

        # Insert subnet before hosts or at end
        lines.insert(insert_pos, "")
        lines.insert(insert_pos + 1, subnet_config)
        lines.insert(insert_pos + 2, "")
        content = '\n'.join(lines)

        # Write updated content
        self.write_config(content)
        logger.info(f"Added DHCP subnet: {network}/{netmask}")
        return True

    def update_subnet(self, network: str, new_netmask: str = None, new_range_start: str = None,
                      new_range_end: str = None, new_options: Dict[str, str] = None) -> bool:
        """Update an existing subnet"""
        subnet = self.get_subnet(network)
        if not subnet:
            raise ValueError(f"Subnet {network} not found")

        # Validate new values if provided
        if new_netmask and not self.validate_netmask(new_netmask):
            raise ValueError(f"Invalid netmask: {new_netmask}")
        if new_range_start and not self.validate_ip_address(new_range_start):
            raise ValueError(f"Invalid range start IP: {new_range_start}")
        if new_range_end and not self.validate_ip_address(new_range_end):
            raise ValueError(f"Invalid range end IP: {new_range_end}")

        # Use current values if not updating
        netmask = new_netmask or subnet.netmask
        range_start = new_range_start if new_range_start is not None else subnet.range_start
        range_end = new_range_end if new_range_end is not None else subnet.range_end
        options = new_options if new_options is not None else subnet.options

        # Validate range is within subnet
        if range_start and not self.ip_in_subnet(range_start, network, netmask):
            raise ValueError(f"Range start {range_start} is not in subnet {network}/{netmask}")
        if range_end and not self.ip_in_subnet(range_end, network, netmask):
            raise ValueError(f"Range end {range_end} is not in subnet {network}/{netmask}")

        # Create backup before modification
        self.create_backup()

        # Update the subnet
        subnet.netmask = netmask
        subnet.range_start = range_start
        subnet.range_end = range_end
        subnet.options = options

        # Replace in configuration
        result = self._replace_subnet_in_config(network, subnet)
        logger.info(f"Updated DHCP subnet: {network}")
        return result

    def delete_subnet(self, network: str) -> bool:
        """Delete a subnet declaration"""
        subnet = self.get_subnet(network)
        if not subnet:
            raise ValueError(f"Subnet {network} not found")

        # Create backup before modification
        self.create_backup()

        # Read current content
        content = self.read_config()

        # Use line-based parsing
        lines = content.split('\n')
        new_lines = []
        i = 0
        deleted = False

        while i < len(lines):
            line = lines[i]

            # Check if this is the start of our target subnet
            subnet_start = re.match(rf'subnet\s+{re.escape(network)}\s+netmask\s+\S+\s*\{{', line.strip())
            if subnet_start and not deleted:
                # Skip this subnet block
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

        # Clean up extra whitespace
        new_content = re.sub(r'\n\s*\n\s*\n', '\n\n', new_content)

        self.write_config(new_content)
        logger.info(f"Deleted DHCP subnet: {network}")
        return True

    def _replace_subnet_in_config(self, network: str, new_subnet: DHCPSubnet) -> bool:
        """Replace a subnet declaration in the configuration"""
        content = self.read_config()

        lines = content.split('\n')
        new_lines = []
        i = 0
        replaced = False

        while i < len(lines):
            line = lines[i]

            # Check if this is the start of our target subnet
            subnet_start = re.match(rf'subnet\s+{re.escape(network)}\s+netmask\s+\S+\s*\{{', line.strip())
            if subnet_start and not replaced:
                # Skip this subnet block
                brace_count = line.count('{') - line.count('}')
                i += 1

                # Skip until we close the block
                while i < len(lines) and brace_count > 0:
                    brace_count += lines[i].count('{') - lines[i].count('}')
                    i += 1

                # Insert the new subnet config
                new_lines.append(new_subnet.to_dhcp_config())
                replaced = True
            else:
                new_lines.append(line)
                i += 1

        new_content = '\n'.join(new_lines)
        self.write_config(new_content)
        return True

    def parse_zones(self) -> List[DHCPZone]:
        """Parse all zone declarations from the configuration"""
        content = self.read_config()
        zones = []
        logger.debug("Parsing DHCP zone declarations")

        lines = content.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Look for zone declaration start: zone "name" {
            zone_match = re.match(r'zone\s+"([^"]+)"\s*\{', line)
            if zone_match:
                zone_name = zone_match.group(1).rstrip('.')  # Remove trailing dot for storage
                primary = None
                key_name = None
                secondary = []

                # Parse the zone block (limit to 50 lines)
                block_end = min(i + 50, len(lines))
                brace_count = 1
                j = i + 1

                while j < block_end and brace_count > 0:
                    block_line = lines[j].strip()

                    # Count braces
                    brace_count += block_line.count('{') - block_line.count('}')

                    # Extract primary server
                    if not primary:
                        primary_match = re.match(r'primary\s+([0-9.]+)\s*;', block_line)
                        if primary_match:
                            primary = primary_match.group(1)

                    # Extract key
                    if not key_name:
                        key_match = re.match(r'key\s+([a-zA-Z0-9_-]+)\s*;', block_line)
                        if key_match:
                            key_name = key_match.group(1)

                    # Extract secondary servers
                    sec_match = re.match(r'secondary\s+([0-9.]+)\s*;', block_line)
                    if sec_match:
                        secondary.append(sec_match.group(1))

                    j += 1

                    if brace_count == 0:
                        break

                # Only add zones with at least a primary server
                if primary:
                    zones.append(DHCPZone(zone_name, primary, key_name, secondary))

                i = j
            else:
                i += 1

        logger.debug(f"Parsed {len(zones)} DHCP zone declarations")
        return zones

    def get_zone(self, zone_name: str) -> Optional[DHCPZone]:
        """Get a specific zone by name"""
        # Normalize zone name (remove trailing dot for comparison)
        zone_name = zone_name.rstrip('.')
        zones = self.parse_zones()
        for zone in zones:
            if zone.zone_name.rstrip('.') == zone_name:
                return zone
        return None

    def add_zone(self, zone_name: str, primary: str, key_name: str = None, secondary: List[str] = None) -> bool:
        """Add a new zone declaration"""
        # Validate inputs
        if not self.validate_zone_name(zone_name):
            raise ValueError(f"Invalid zone name: {zone_name}")
        if not self.validate_ip_address(primary):
            raise ValueError(f"Invalid primary server IP: {primary}")
        if secondary:
            for sec in secondary:
                if not self.validate_ip_address(sec):
                    raise ValueError(f"Invalid secondary server IP: {sec}")

        # Check if zone already exists
        if self.get_zone(zone_name):
            raise ValueError(f"Zone {zone_name} already exists")

        # Create backup before modification
        self.create_backup()

        # Read current content
        content = self.read_config()

        # Create new zone entry
        new_zone = DHCPZone(zone_name, primary, key_name, secondary or [])
        zone_config = new_zone.to_dhcp_config()

        # Find good place to insert (at end before hosts)
        lines = content.split('\n')
        insert_pos = len(lines)

        # Look for first host or subnet declaration
        for i, line in enumerate(lines):
            if (re.match(r'host\s+\S+\s*\{', line.strip()) or
                re.match(r'subnet\s+\S+\s+netmask\s+\S+\s*\{', line.strip())):
                insert_pos = i
                break

        # Insert zone
        lines.insert(insert_pos, "")
        lines.insert(insert_pos + 1, zone_config)
        lines.insert(insert_pos + 2, "")
        content = '\n'.join(lines)

        # Write updated content
        self.write_config(content)
        logger.info(f"Added DHCP zone: {zone_name} (primary: {primary})")
        return True

    def update_zone(self, zone_name: str, new_primary: str = None, new_key_name: str = None,
                    new_secondary: List[str] = None) -> bool:
        """Update an existing zone"""
        zone = self.get_zone(zone_name)
        if not zone:
            raise ValueError(f"Zone {zone_name} not found")

        # Validate new values if provided
        if new_primary and not self.validate_ip_address(new_primary):
            raise ValueError(f"Invalid primary server IP: {new_primary}")
        if new_secondary:
            for sec in new_secondary:
                if not self.validate_ip_address(sec):
                    raise ValueError(f"Invalid secondary server IP: {sec}")

        # Use current values if not updating
        primary = new_primary or zone.primary
        key_name = new_key_name if new_key_name is not None else zone.key_name
        secondary = new_secondary if new_secondary is not None else zone.secondary

        # Create backup before modification
        self.create_backup()

        # Update the zone
        zone.primary = primary
        zone.key_name = key_name
        zone.secondary = secondary

        # Replace in configuration
        result = self._replace_zone_in_config(zone_name, zone)
        logger.info(f"Updated DHCP zone: {zone_name}")
        return result

    def delete_zone(self, zone_name: str) -> bool:
        """Delete a zone declaration"""
        zone = self.get_zone(zone_name)
        if not zone:
            raise ValueError(f"Zone {zone_name} not found")

        # Create backup before modification
        self.create_backup()

        # Read current content
        content = self.read_config()

        # Use line-based parsing
        lines = content.split('\n')
        new_lines = []
        i = 0
        deleted = False

        while i < len(lines):
            line = lines[i]

            # Check if this is the start of our target zone
            zone_start = re.match(rf'zone\s+"([^"]+)"\s*\{{', line.strip())
            if zone_start and not deleted:
                found_zone = zone_start.group(1).rstrip('.')
                if found_zone == zone_name.rstrip('.'):
                    # Skip this zone block
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
            else:
                new_lines.append(line)
                i += 1

        new_content_zones = '\n'.join(new_lines)

        # Clean up extra whitespace
        new_content_zones = re.sub(r'\n\s*\n\s*\n', '\n\n', new_content_zones)

        self.write_config(new_content_zones)
        logger.info(f"Deleted DHCP zone: {zone_name}")
        return True

    def parse_global_config(self) -> DHCPGlobalConfig:
        """Parse global configuration settings from the DHCP config file"""
        logger.debug("Parsing global DHCP configuration")
        content = self.read_config()
        lines = content.split('\n')

        # Default values
        config = DHCPGlobalConfig()

        # Parse global settings (stop at first subnet, host, or zone declaration)
        for line in lines:
            stripped = line.strip()

            # Stop parsing at first subnet/host/zone declaration
            if (stripped.startswith('subnet ') or
                stripped.startswith('host ') or
                stripped.startswith('zone ')):
                break

            # Skip comments and empty lines
            if not stripped or stripped.startswith('#'):
                continue

            # Parse default-lease-time
            match = re.match(r'default-lease-time\s+(\d+)\s*;', stripped)
            if match:
                config.default_lease_time = int(match.group(1))
                continue

            # Parse max-lease-time
            match = re.match(r'max-lease-time\s+(\d+)\s*;', stripped)
            if match:
                config.max_lease_time = int(match.group(1))
                continue

            # Parse authoritative
            if stripped == 'authoritative;':
                config.authoritative = True
                continue

            # Parse log-facility
            match = re.match(r'log-facility\s+([a-z0-9-]+)\s*;', stripped)
            if match:
                config.log_facility = match.group(1)
                continue

            # Parse ddns-update-style
            match = re.match(r'ddns-update-style\s+([a-z-]+)\s*;', stripped)
            if match:
                config.ddns_update_style = match.group(1)
                continue

            # Parse ping-check
            match = re.match(r'ping-check\s+(true|false)\s*;', stripped)
            if match:
                config.ping_check = match.group(1) == 'true'
                continue

            # Parse ping-timeout
            match = re.match(r'ping-timeout\s+(\d+)\s*;', stripped)
            if match:
                config.ping_timeout = int(match.group(1))
                continue

            # Parse option domain-name
            match = re.match(r'option\s+domain-name\s+"([^"]+)"\s*;', stripped)
            if match:
                config.domain_name = match.group(1)
                continue

            # Parse option domain-name-servers
            match = re.match(r'option\s+domain-name-servers\s+([^;]+)\s*;', stripped)
            if match:
                config.domain_name_servers = match.group(1).strip()
                continue

            # Parse option ntp-servers
            match = re.match(r'option\s+ntp-servers\s+([^;]+)\s*;', stripped)
            if match:
                config.ntp_servers = match.group(1).strip()
                continue

            # Parse option time-offset
            match = re.match(r'option\s+time-offset\s+(-?\d+)\s*;', stripped)
            if match:
                config.time_offset = int(match.group(1))
                continue

        return config

    def update_global_config(self, new_config: DHCPGlobalConfig) -> bool:
        """Update global configuration settings"""
        # Validate lease times
        if new_config.default_lease_time <= 0:
            raise ValueError("default-lease-time must be positive")
        if new_config.max_lease_time <= 0:
            raise ValueError("max-lease-time must be positive")
        if new_config.max_lease_time < new_config.default_lease_time:
            raise ValueError("max-lease-time must be greater than or equal to default-lease-time")

        # Validate log facility
        valid_facilities = ['daemon', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7']
        if new_config.log_facility and new_config.log_facility not in valid_facilities:
            raise ValueError(f"Invalid log-facility. Must be one of: {', '.join(valid_facilities)}")

        # Validate ddns-update-style
        valid_ddns = ['none', 'interim', 'ad-hoc']
        if new_config.ddns_update_style and new_config.ddns_update_style not in valid_ddns:
            raise ValueError(f"Invalid ddns-update-style. Must be one of: {', '.join(valid_ddns)}")

        # Validate domain name servers (if provided)
        if new_config.domain_name_servers:
            dns_list = [s.strip() for s in new_config.domain_name_servers.split(',')]
            for dns in dns_list:
                if not self.validate_ip_address(dns):
                    raise ValueError(f"Invalid DNS server IP address: {dns}")

        # Validate NTP servers (if provided)
        if new_config.ntp_servers:
            ntp_list = [s.strip() for s in new_config.ntp_servers.split(',')]
            for ntp in ntp_list:
                if not self.validate_ip_address(ntp):
                    raise ValueError(f"Invalid NTP server IP address: {ntp}")

        # Create backup before modification
        self.create_backup()

        # Read current content
        content = self.read_config()
        lines = content.split('\n')

        # Track which global settings we've found and replaced
        replaced_settings = set()
        new_lines = []
        global_section_ended = False

        for line in lines:
            stripped = line.strip()

            # Check if global section has ended
            if (stripped.startswith('subnet ') or
                stripped.startswith('host ') or
                stripped.startswith('zone ')):
                # If we haven't added all global settings yet, add them now
                if not global_section_ended:
                    global_section_ended = True
                    # Add any missing settings
                    self._add_missing_global_settings(new_lines, new_config, replaced_settings)
                    new_lines.append('')  # Empty line before first declaration

                new_lines.append(line)
                continue

            # Replace existing global settings
            if not global_section_ended:
                # Skip empty lines and comments in global section
                if not stripped or stripped.startswith('#'):
                    new_lines.append(line)
                    continue

                # Check and replace each setting
                if re.match(r'default-lease-time\s+\d+\s*;', stripped):
                    if 'default-lease-time' not in replaced_settings:
                        new_lines.append(f"default-lease-time {new_config.default_lease_time};")
                        replaced_settings.add('default-lease-time')
                    continue

                if re.match(r'max-lease-time\s+\d+\s*;', stripped):
                    if 'max-lease-time' not in replaced_settings:
                        new_lines.append(f"max-lease-time {new_config.max_lease_time};")
                        replaced_settings.add('max-lease-time')
                    continue

                if stripped == 'authoritative;':
                    if 'authoritative' not in replaced_settings:
                        if new_config.authoritative:
                            new_lines.append("authoritative;")
                        replaced_settings.add('authoritative')
                    continue

                if re.match(r'log-facility\s+', stripped):
                    if 'log-facility' not in replaced_settings:
                        if new_config.log_facility:
                            new_lines.append(f"log-facility {new_config.log_facility};")
                        replaced_settings.add('log-facility')
                    continue

                if re.match(r'ddns-update-style\s+', stripped):
                    if 'ddns-update-style' not in replaced_settings:
                        if new_config.ddns_update_style:
                            new_lines.append(f"ddns-update-style {new_config.ddns_update_style};")
                        replaced_settings.add('ddns-update-style')
                    continue

                if re.match(r'ping-check\s+', stripped):
                    if 'ping-check' not in replaced_settings:
                        if new_config.ping_check:
                            new_lines.append("ping-check true;")
                            if new_config.ping_timeout:
                                new_lines.append(f"ping-timeout {new_config.ping_timeout};")
                        replaced_settings.add('ping-check')
                        replaced_settings.add('ping-timeout')
                    continue

                if re.match(r'ping-timeout\s+', stripped):
                    if 'ping-timeout' not in replaced_settings:
                        # Skip - handled with ping-check
                        replaced_settings.add('ping-timeout')
                    continue

                if re.match(r'option\s+domain-name\s+"', stripped):
                    if 'domain-name' not in replaced_settings:
                        if new_config.domain_name:
                            new_lines.append(f'option domain-name "{new_config.domain_name}";')
                        replaced_settings.add('domain-name')
                    continue

                if re.match(r'option\s+domain-name-servers\s+', stripped):
                    if 'domain-name-servers' not in replaced_settings:
                        if new_config.domain_name_servers:
                            new_lines.append(f"option domain-name-servers {new_config.domain_name_servers};")
                        replaced_settings.add('domain-name-servers')
                    continue

                if re.match(r'option\s+ntp-servers\s+', stripped):
                    if 'ntp-servers' not in replaced_settings:
                        if new_config.ntp_servers:
                            new_lines.append(f"option ntp-servers {new_config.ntp_servers};")
                        replaced_settings.add('ntp-servers')
                    continue

                if re.match(r'option\s+time-offset\s+', stripped):
                    if 'time-offset' not in replaced_settings:
                        if new_config.time_offset is not None:
                            new_lines.append(f"option time-offset {new_config.time_offset};")
                        replaced_settings.add('time-offset')
                    continue

                # Keep any other lines in global section
                new_lines.append(line)
            else:
                # After global section, keep everything as-is
                new_lines.append(line)

        # If no declarations found (empty file or only global settings), add missing settings
        if not global_section_ended:
            self._add_missing_global_settings(new_lines, new_config, replaced_settings)

        new_content = '\n'.join(new_lines)
        self.write_config(new_content)
        logger.info("Updated global DHCP configuration")
        return True

    def _add_missing_global_settings(self, lines: List[str], config: DHCPGlobalConfig, replaced: set) -> None:
        """Add global settings that weren't found in the config file"""
        if 'default-lease-time' not in replaced:
            lines.append(f"default-lease-time {config.default_lease_time};")

        if 'max-lease-time' not in replaced:
            lines.append(f"max-lease-time {config.max_lease_time};")

        if 'authoritative' not in replaced and config.authoritative:
            lines.append("authoritative;")

        if 'log-facility' not in replaced and config.log_facility:
            lines.append(f"log-facility {config.log_facility};")

        if 'ddns-update-style' not in replaced and config.ddns_update_style:
            lines.append(f"ddns-update-style {config.ddns_update_style};")

        if 'ping-check' not in replaced and config.ping_check:
            lines.append("ping-check true;")
            if config.ping_timeout:
                lines.append(f"ping-timeout {config.ping_timeout};")

        if 'domain-name' not in replaced and config.domain_name:
            lines.append(f'option domain-name "{config.domain_name}";')

        if 'domain-name-servers' not in replaced and config.domain_name_servers:
            lines.append(f"option domain-name-servers {config.domain_name_servers};")

        if 'ntp-servers' not in replaced and config.ntp_servers:
            lines.append(f"option ntp-servers {config.ntp_servers};")

        if 'time-offset' not in replaced and config.time_offset is not None:
            lines.append(f"option time-offset {config.time_offset};")

    def _replace_zone_in_config(self, zone_name: str, new_zone: DHCPZone) -> bool:
        """Replace a zone declaration in the configuration"""
        content = self.read_config()

        lines = content.split('\n')
        new_lines = []
        i = 0
        replaced = False

        while i < len(lines):
            line = lines[i]

            # Check if this is the start of our target zone
            zone_start = re.match(rf'zone\s+"([^"]+)"\s*\{{', line.strip())
            if zone_start and not replaced:
                found_zone = zone_start.group(1).rstrip('.')
                if found_zone == zone_name.rstrip('.'):
                    # Skip this zone block
                    brace_count = line.count('{') - line.count('}')
                    i += 1

                    # Skip until we close the block
                    while i < len(lines) and brace_count > 0:
                        brace_count += lines[i].count('{') - lines[i].count('}')
                        i += 1

                    # Insert the new zone config
                    new_lines.append(new_zone.to_dhcp_config())
                    replaced = True
                else:
                    new_lines.append(line)
                    i += 1
            else:
                new_lines.append(line)
                i += 1

        new_content_final = '\n'.join(new_lines)
        self.write_config(new_content_final)
        return True