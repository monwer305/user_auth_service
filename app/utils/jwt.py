import jwt
import datetime
from datetime import timezone
import uuid
from app.config import settings
from typing import Dict, Any

ALGORITHM = "HS256"

def _utc_now():
    return datetime.datetime.utcnow()

def create_reset_token(subject: str, email: str, expires_minutes: int = 30) -> str:
    now = _utc_now()
    exp = now + datetime.timedelta(minutes=expires_minutes)
    payload = {
        "sub": subject,
        "email": email,
        "type": "reset",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)


def create_access_token(subject: str, email: str, role:str, expires_minutes: int = None) -> str:
    if expires_minutes is None:
        expires_minutes = settings.ACCESS_TOKEN_EXPIRES_MIN
    now = now = datetime.datetime.now(timezone.utc)
    exp = now + datetime.timedelta(minutes=expires_minutes)
    payload = {
        "sub": subject,
        "email": email,
        "role":role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)

def create_refresh_token(subject: str, email: str, expires_days: int = None) -> Dict[str, Any]:
    if expires_days is None:
        expires_days = settings.REFRESH_TOKEN_EXPIRES_DAYS
    now = _utc_now()
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
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[ALGORITHM],leeway=60)
