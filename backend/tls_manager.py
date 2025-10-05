"""
TLS Certificate Manager
Handles TLS certificate information retrieval, validation, and nginx management
"""

import subprocess
import os
import re
import logging
from datetime import datetime
from typing import Dict, Optional, Tuple, List

logger = logging.getLogger(__name__)


class TLSCertificateInfo:
    """Holds TLS certificate information"""

    def __init__(self, subject: str, issuer: str, valid_from: str, valid_to: str,
                 days_until_expiry: int, san_dns: List[str], san_ip: List[str],
                 fingerprint: str, is_self_signed: bool):
        self.subject = subject
        self.issuer = issuer
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.days_until_expiry = days_until_expiry
        self.san_dns = san_dns
        self.san_ip = san_ip
        self.fingerprint = fingerprint
        self.is_self_signed = is_self_signed

    def to_dict(self) -> Dict:
        """Return certificate info as dictionary"""
        return {
            'subject': self.subject,
            'issuer': self.issuer,
            'valid_from': self.valid_from,
            'valid_to': self.valid_to,
            'days_until_expiry': self.days_until_expiry,
            'san_dns': self.san_dns,
            'san_ip': self.san_ip,
            'fingerprint': self.fingerprint,
            'is_self_signed': self.is_self_signed
        }


def get_certificate_info(cert_path: str) -> TLSCertificateInfo:
    """
    Parse certificate file and extract information using OpenSSL

    Args:
        cert_path: Path to certificate file

    Returns:
        TLSCertificateInfo object with certificate details

    Raises:
        FileNotFoundError: If certificate file doesn't exist
        PermissionError: If certificate file is not readable
        ValueError: If certificate cannot be parsed
    """
    if not os.path.exists(cert_path):
        logger.error(f"TLS certificate file not found: {cert_path}")
        raise FileNotFoundError(f"Certificate file not found: {cert_path}")

    if not os.access(cert_path, os.R_OK):
        logger.error(f"TLS certificate file not readable: {cert_path}")
        raise PermissionError(f"Cannot read certificate file: {cert_path}")

    try:
        # Get certificate text output
        result = subprocess.run(
            ['/usr/bin/openssl', 'x509', '-in', cert_path, '-text', '-noout'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            logger.error(f"Failed to parse TLS certificate: {result.stderr}")
            raise ValueError(f"Failed to parse certificate: {result.stderr}")

        cert_text = result.stdout

        # Extract subject
        subject_match = re.search(r'Subject:\s*(.+)$', cert_text, re.MULTILINE)
        subject = subject_match.group(1).strip() if subject_match else "Unknown"

        # Extract issuer
        issuer_match = re.search(r'Issuer:\s*(.+)$', cert_text, re.MULTILINE)
        issuer = issuer_match.group(1).strip() if issuer_match else "Unknown"

        # Extract valid from date
        valid_from_match = re.search(r'Not Before\s*:\s*(.+)$', cert_text, re.MULTILINE)
        valid_from = valid_from_match.group(1).strip() if valid_from_match else "Unknown"

        # Extract valid to date
        valid_to_match = re.search(r'Not After\s*:\s*(.+)$', cert_text, re.MULTILINE)
        valid_to = valid_to_match.group(1).strip() if valid_to_match else "Unknown"

        # Calculate days until expiry
        days_until_expiry = 0
        if valid_to != "Unknown":
            try:
                # Parse OpenSSL date format: "Jan  1 00:00:00 2035 GMT"
                expiry_date = datetime.strptime(valid_to, "%b %d %H:%M:%S %Y %Z")
                days_until_expiry = (expiry_date - datetime.utcnow()).days
            except ValueError:
                logger.warning(f"Could not parse TLS certificate expiry date: {valid_to}")

        # Extract SANs (Subject Alternative Names)
        san_dns = []
        san_ip = []
        san_match = re.search(r'X509v3 Subject Alternative Name:\s*\n\s*(.+?)(?:\n\s*\n|\n\s*X509v3|\Z)', cert_text, re.MULTILINE | re.DOTALL)
        if san_match:
            san_text = san_match.group(1)
            # Parse DNS entries
            dns_entries = re.findall(r'DNS:([^,\s]+)', san_text)
            san_dns = [dns.strip() for dns in dns_entries]
            # Parse IP entries
            ip_entries = re.findall(r'IP Address:([^,\s]+)', san_text)
            san_ip = [ip.strip() for ip in ip_entries]

        # Get fingerprint (SHA256)
        fingerprint_result = subprocess.run(
            ['/usr/bin/openssl', 'x509', '-in', cert_path, '-noout', '-fingerprint', '-sha256'],
            capture_output=True,
            text=True,
            timeout=5
        )
        fingerprint = "Unknown"
        if fingerprint_result.returncode == 0:
            fp_match = re.search(r'SHA256 Fingerprint=(.+)$', fingerprint_result.stdout)
            if fp_match:
                fingerprint = fp_match.group(1).strip()

        # Determine if self-signed (subject == issuer)
        is_self_signed = subject == issuer

        logger.debug(f"Successfully parsed TLS certificate: {cert_path}")

        return TLSCertificateInfo(
            subject=subject,
            issuer=issuer,
            valid_from=valid_from,
            valid_to=valid_to,
            days_until_expiry=days_until_expiry,
            san_dns=san_dns,
            san_ip=san_ip,
            fingerprint=fingerprint,
            is_self_signed=is_self_signed
        )

    except subprocess.TimeoutExpired:
        logger.error(f"Timeout parsing TLS certificate: {cert_path}")
        raise ValueError("Certificate parsing timed out")
    except Exception as e:
        logger.error(f"Error parsing TLS certificate {cert_path}: {str(e)}")
        raise


def validate_certificate_file(cert_path: str) -> Tuple[bool, str]:
    """
    Validate that certificate file is readable and valid

    Args:
        cert_path: Path to certificate file

    Returns:
        Tuple of (is_valid, message)
    """
    try:
        # Check file exists
        if not os.path.exists(cert_path):
            return False, f"Certificate file not found: {cert_path}"

        # Check file is readable
        if not os.access(cert_path, os.R_OK):
            return False, f"Cannot read certificate file: {cert_path}"

        # Try to parse certificate
        result = subprocess.run(
            ['/usr/bin/openssl', 'x509', '-in', cert_path, '-noout', '-subject'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            logger.warning(f"Invalid TLS certificate file: {cert_path} - {result.stderr}")
            return False, f"Invalid certificate file: {result.stderr}"

        # Check if expired
        expiry_result = subprocess.run(
            ['/usr/bin/openssl', 'x509', '-in', cert_path, '-noout', '-checkend', '0'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if expiry_result.returncode != 0:
            logger.warning(f"TLS certificate has expired: {cert_path}")
            return False, "Certificate has expired"

        logger.debug(f"TLS certificate validation successful: {cert_path}")
        return True, "Certificate is valid"

    except subprocess.TimeoutExpired:
        logger.error(f"Timeout validating TLS certificate: {cert_path}")
        return False, "Certificate validation timed out"
    except Exception as e:
        logger.error(f"Error validating TLS certificate {cert_path}: {str(e)}")
        return False, f"Validation error: {str(e)}"


