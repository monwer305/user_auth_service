import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class User(Base):
    """
    Represents a user in the authentication system.

    Attributes:
        id (int): Primary key for the user.
        email (str): Unique email address of the user.
        password (str): Hashed password for authentication.
        is_active (bool): Indicates if the user account is active.
        is_admin (bool): Backward-compatible admin flag.
        role (str): Role of the user ("user", "admin", "superadmin").
        disabled (bool): Indicates if the user account is disabled.
        created_at (datetime): Timestamp of user creation.
        refresh_tokens (List[RefreshToken]): Associated refresh tokens for the user.
    """

    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password = Column(String(255), nullable=False)  # hashed
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)  # keep for backward compatibility
    role = Column(String(50), default="user")  # "user", "admin", "superadmin"
    disabled = Column(Boolean, default=False)  # allow disabling users
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    refresh_tokens = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
    )


class RefreshToken(Base):
    """
    Represents a refresh token for user authentication.

    Attributes:
        id (int): Primary key.
        jti (str): JWT ID, unique identifier for the token.
        token_hash (str): Hashed value of the refresh token.
        revoked (bool): Indicates if the token is revoked.
        user_id (int): Foreign key referencing the user.
        created_at (datetime): Timestamp when the token was created.
        expires_at (datetime): Expiration timestamp of the token.
        user (User): Relationship to the associated user.
    """

    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(64), nullable=False, unique=True, index=True)  # JWT ID
    token_hash = Column(String(255), nullable=False)  # hashed token value
    revoked = Column(Boolean, default=False)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

    user = relationship("User", back_populates="refresh_tokens")
    __table_args__ = (UniqueConstraint("jti", name="uq_refresh_jti"),)
