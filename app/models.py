from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, UniqueConstraint
from sqlalchemy.orm import declarative_base, relationship
import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password = Column(String(255), nullable=False)  # hashed
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)  # keep for backward compatibility
    role = Column(String(50), default="user")  # "user", "admin", "superadmin"
    disabled = Column(Boolean, default=False)  # allow disabling users
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(64), nullable=False, unique=True, index=True)  # JWT ID
    token_hash = Column(String(255), nullable=False)  # hashed token value
    revoked = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

    user = relationship("User", back_populates="refresh_tokens")
    __table_args__ = (UniqueConstraint("jti", name="uq_refresh_jti"),)
