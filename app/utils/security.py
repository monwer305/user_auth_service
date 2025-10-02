from hashlib import sha256

from passlib.context import CryptContext

# CryptContext for password hashing using Argon2
pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    """
    Hashes a password using Argon2.

    Args:
        password: Plain text password.

    Returns:
        Hashed password string.
    """
    return pwd_ctx.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain password against a hashed password.

    Args:
        plain_password: User input password.
        hashed_password: Stored hashed password.

    Returns:
        True if match, False otherwise.
    """
    return pwd_ctx.verify(plain_password, hashed_password)


def hash_token(token: str) -> str:
    """
    Hashes a token using SHA256 for secure server-side storage.

    Args:
        token: Raw token string.

    Returns:
        SHA256 hashed token string.
    """
    return sha256(token.encode("utf-8")).hexdigest()
