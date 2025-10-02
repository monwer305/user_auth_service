import datetime
import uuid
from datetime import timezone
from typing import Any, Dict

import jwt

from app.config_utils import ConfigMapper

ALGORITHM = "HS256"


def create_reset_token(subject: str, email: str, expires_minutes: int = 30) -> str:
    """
    Generates a JWT reset token for password reset functionality.

    Args:
        subject (str): The subject identifier (e.g., user ID).
        email (str): The user's email address.
        expires_minutes (int, optional): Token expiration time in minutes. Defaults to 30.

    Returns:
        str: Encoded JWT reset token as a string.
    """
    settings = ConfigMapper.get()
    now = datetime.datetime.now(timezone.utc)
    exp = now + datetime.timedelta(minutes=expires_minutes)
    payload = {
        "sub": subject,
        "email": email,
        "type": "reset",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)


def create_access_token(
    subject: str, email: str, role: str, expires_minutes: int = None
) -> str:
    """
    Generates a JWT access token for a user.

    Args:
        subject (str): The subject identifier (e.g., user ID).
        email (str): The user's email address.
        role (str): The user's role.
        expires_minutes (int, optional): Token expiration time in minutes. Defaults to config value.

    Returns:
        str: Encoded JWT access token.
    """
    settings = ConfigMapper.get()
    if expires_minutes is None:
        expires_minutes = settings.ACCESS_TOKEN_EXPIRES_MIN
    now = datetime.datetime.now(timezone.utc)
    exp = now + datetime.timedelta(minutes=expires_minutes)
    payload = {
        "sub": subject,
        "email": email,
        "role": role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)


def create_refresh_token(
    subject: str, email: str, expires_days: int = None
) -> Dict[str, Any]:
    """
    Generates a JWT refresh token for a given subject and email.

    Args:
        subject (str): The subject identifier (e.g., user ID).
        email (str): The user's email address.
        expires_days (int, optional): Number of days until token expiration. Defaults to config value.

    Returns:
        Dict[str, Any]: A dictionary containing the token, its unique ID (jti), and expiration datetime.
    """
    settings = ConfigMapper.get()
    if expires_days is None:
        expires_days = settings.REFRESH_TOKEN_EXPIRES_DAYS
    now = datetime.datetime.now(timezone.utc)
    exp = now + datetime.timedelta(days=expires_days)
    jti = str(uuid.uuid4())
    payload = {
        "sub": subject,
        "email": email,
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti,
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)
    return {"token": token, "jti": jti, "expires_at": exp}


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decodes a JWT token using the configured secret and algorithm.

    Args:
        token (str): The JWT token to decode.

    Returns:
        Dict[str, Any]: The decoded token payload.

    Raises:
        jwt.DecodeError: If the token is invalid or cannot be decoded.
        jwt.ExpiredSignatureError: If the token has expired.
    """
    settings = ConfigMapper.get()
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[ALGORITHM], leeway=60)
