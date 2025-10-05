"""
Authentication Manager for ISC Web DHCP Manager
Handles password hashing, verification, and JWT token management
"""

import bcrypt
import jwt
import logging
from datetime import datetime, timedelta
from typing import Tuple

logger = logging.getLogger(__name__)


def hash_password(password: str) -> str:
    """
    Generate bcrypt hash for password

    Args:
        password: Plain text password

    Returns:
        Bcrypt hash string

    Raises:
        ValueError: If password is empty
    """
    if not password:
        logger.error("Attempted to hash empty password")
        raise ValueError("Password cannot be empty")

    if len(password) < 8:
        logger.warning("Password shorter than recommended minimum (8 characters)")

    # Generate salt and hash password (cost factor 12)
    salt = bcrypt.gensalt(rounds=12)
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)

    logger.debug("Generated password hash")
    return password_hash.decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify password against bcrypt hash

    Args:
        password: Plain text password to verify
        password_hash: Bcrypt hash to compare against

    Returns:
        True if password matches, False otherwise
    """
    if not password or not password_hash:
        logger.warning("Password verification attempted with empty password or hash")
        return False

    try:
        matches = bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

        if matches:
            logger.info("Password verification successful")
        else:
            logger.warning("Password verification failed - incorrect password")

        return matches

    except Exception as e:
        logger.error(f"Password verification error: {str(e)}")
        return False


def generate_token(secret_key: str, expires_hours: int = 24) -> Tuple[str, str]:
    """
    Generate JWT authentication token

    Args:
        secret_key: Secret key for signing token
        expires_hours: Token validity period in hours (default: 24)

    Returns:
        Tuple of (token_string, expiry_timestamp_iso)

    Raises:
        ValueError: If secret_key is empty
    """
    if not secret_key:
        logger.error("Attempted to generate token with empty secret key")
        raise ValueError("Secret key cannot be empty")

    if expires_hours < 1 or expires_hours > 168:  # Max 1 week
        logger.warning(f"Token expiry hours out of recommended range: {expires_hours}")

    # Calculate expiry time
    expiry = datetime.utcnow() + timedelta(hours=expires_hours)

    # Create token payload
    payload = {
        'exp': expiry,
        'iat': datetime.utcnow(),
        'authenticated': True
    }

    # Generate token
    token = jwt.encode(payload, secret_key, algorithm='HS256')

    logger.info(f"Generated authentication token (expires: {expiry.isoformat()})")

    return token, expiry.isoformat() + 'Z'


def verify_token(token: str, secret_key: str) -> Tuple[bool, str]:
    """
    Verify JWT authentication token

    Args:
        token: JWT token string to verify
        secret_key: Secret key used to sign token

    Returns:
        Tuple of (is_valid, error_message)
        is_valid is True if token is valid, False otherwise
        error_message contains reason if invalid, empty string if valid
    """
    if not token:
        logger.warning("Token verification attempted with empty token")
        return False, "No token provided"

    if not secret_key:
        logger.error("Token verification attempted with empty secret key")
        return False, "Invalid configuration"

    try:
        # Decode and verify token
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])

        # Check if authenticated flag is present
        if not payload.get('authenticated'):
            logger.warning("Token missing authenticated flag")
            return False, "Invalid token"

        logger.debug("Token verification successful")
        return True, ""

    except jwt.ExpiredSignatureError:
        logger.info("Token verification failed - token expired")
        return False, "Token has expired"

    except jwt.InvalidTokenError as e:
        logger.warning(f"Token verification failed - invalid token: {str(e)}")
        return False, "Invalid token"

    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
        return False, "Token verification failed"
