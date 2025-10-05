"""
DHCP Lease Parser
Parses ISC DHCP Server lease file (dhcpd.leases) to extract current lease information
"""

import re
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DHCPLease:
    """Represents a DHCP lease entry"""
    ip: str
    mac: str
    starts: str
    ends: str
    state: str
    hostname: Optional[str] = None
    binding_state: str = "unknown"


class LeaseParser:
    """Parser for ISC DHCP Server lease files"""

    def __init__(self, leases_path: str):
        """
        Initialize lease parser

        Args:
            leases_path: Path to dhcpd.leases file
        """
        self.leases_path = leases_path
        logger.debug(f"Initialized LeaseParser with path: {leases_path}")

    def read_leases_file(self) -> str:
        """
        Read the DHCP leases file

        Returns:
            Content of the leases file

        Raises:
            FileNotFoundError: If leases file doesn't exist
            PermissionError: If file is not readable
        """
        try:
            with open(self.leases_path, 'r') as f:
                content = f.read()
            logger.debug(f"Read {len(content)} bytes from leases file")
            return content
        except FileNotFoundError:
            logger.error(f"Leases file not found: {self.leases_path}")
            raise
        except PermissionError:
            logger.error(f"Permission denied reading leases file: {self.leases_path}")
            raise
        except Exception as e:
            logger.error(f"Error reading leases file: {str(e)}")
            raise

    def parse_leases(self, active_only: bool = False) -> List[DHCPLease]:
        """
        Parse DHCP leases from the leases file

        Args:
            active_only: If True, only return active leases

        Returns:
            List of DHCPLease objects
        """
        try:
            content = self.read_leases_file()
            leases = []

            # ISC DHCP lease format:
            # lease 192.168.1.100 {
            #   starts 4 2024/01/15 10:30:00;
            #   ends 4 2024/01/15 11:30:00;
            #   binding state active;
            #   hardware ethernet 00:11:22:33:44:55;
            #   client-hostname "hostname";
            # }

            # Find all lease blocks
            lease_pattern = r'lease\s+([\d.]+)\s*\{([^}]+)\}'
            lease_matches = re.finditer(lease_pattern, content, re.MULTILINE)

            # Track the latest lease for each IP (file may contain historical entries)
            latest_leases = {}

            for match in lease_matches:
                ip = match.group(1)
                lease_block = match.group(2)

                # Extract lease details
                starts_match = re.search(r'starts\s+\d+\s+([\d/]+\s+[\d:]+);', lease_block)
                ends_match = re.search(r'ends\s+\d+\s+([\d/]+\s+[\d:]+);', lease_block)
                mac_match = re.search(r'hardware\s+ethernet\s+([\da-fA-F:]+);', lease_block)
                hostname_match = re.search(r'client-hostname\s+"([^"]+)";', lease_block)
                binding_state_match = re.search(r'binding\s+state\s+(\w+);', lease_block)

                if not mac_match:
                    # Skip leases without MAC address
                    continue

                starts = starts_match.group(1) if starts_match else "unknown"
                ends = ends_match.group(1) if ends_match else "unknown"
                mac = mac_match.group(1).lower()
                hostname = hostname_match.group(1) if hostname_match else None
                binding_state = binding_state_match.group(1) if binding_state_match else "unknown"

                # Determine state based on binding state and end time
                state = self._determine_lease_state(ends, binding_state)

                lease = DHCPLease(
                    ip=ip,
                    mac=mac,
                    starts=starts,
                    ends=ends,
                    state=state,
                    hostname=hostname,
                    binding_state=binding_state
                )

                # Store only the latest lease for each IP
                # The lease file is appended to, so later entries are more recent
                latest_leases[ip] = lease

            # Convert to list
            leases = list(latest_leases.values())

            # Filter to active leases if requested
            if active_only:
                leases = [l for l in leases if l.state == 'active']

            logger.info(f"Parsed {len(leases)} leases from {self.leases_path}" +
                       (f" (active only)" if active_only else ""))
            return leases

        except Exception as e:
            logger.error(f"Error parsing leases: {str(e)}")
            raise

    def _determine_lease_state(self, ends: str, binding_state: str) -> str:
        """
        Determine the current state of a lease

        Args:
            ends: Lease end time string (format: YYYY/MM/DD HH:MM:SS)
            binding_state: Binding state from lease file

        Returns:
            State string: 'active', 'expired', 'free', or based on binding_state
        """
        try:
            # If binding state is explicitly set, use it
            if binding_state == 'free':
                return 'free'
            elif binding_state == 'abandoned':
                return 'abandoned'
            elif binding_state == 'backup':
                return 'backup'

            # Check if lease has expired by comparing end time
            if ends != "unknown":
                try:
                    # Parse ISC DHCP date format: YYYY/MM/DD HH:MM:SS
                    # ISC DHCP uses UTC times
                    end_time = datetime.strptime(ends, '%Y/%m/%d %H:%M:%S')
                    # Compare using UTC time
                    from datetime import timezone
                    now = datetime.now(timezone.utc).replace(tzinfo=None)

                    if now > end_time:
                        return 'expired'
                    elif binding_state == 'active':
                        return 'active'
                except ValueError:
                    logger.warning(f"Could not parse end time: {ends}")

            # Default based on binding state
            return binding_state if binding_state != 'unknown' else 'active'

        except Exception as e:
            logger.warning(f"Error determining lease state: {str(e)}")
            return 'unknown'

    def get_active_leases(self) -> List[DHCPLease]:
        """
        Get only currently active leases

        Returns:
            List of active DHCPLease objects
        """
        return self.parse_leases(active_only=True)

    def get_all_leases(self) -> List[DHCPLease]:
        """
        Get all leases including expired and freed

        Returns:
            List of all DHCPLease objects
        """
        return self.parse_leases(active_only=False)
