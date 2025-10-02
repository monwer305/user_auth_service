from typing import Dict, Tuple

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session

from app.config_utils import ConfigMapper
from app.db import get_db
from app.models import RefreshToken, User
from app.schemas import TokenResponse
from app.utils.jwt import create_access_token, create_refresh_token, decode_token
from app.utils.security import hash_token, verify_password

security = HTTPBasic()
router = APIRouter(prefix="/auth", tags=["auth"])


def _store_refresh_token(
    db: Session, token_str: str, user_id: int, jti: str, expires_at
) -> RefreshToken:
    """Store a new refresh token in the database.

    Args:
        db (Session): Database session.
        token_str (str): Raw refresh token.
        user_id (int): User ID.
        jti (str): Token unique identifier.
        expires_at (datetime): Token expiry time.

    Returns:
        RefreshToken: Stored refresh token object.
    """
    rt = RefreshToken(
        jti=jti,
        token_hash=hash_token(token_str),
        user_id=user_id,
        expires_at=expires_at,
    )
    try:
        db.add(rt)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return rt


def _rotate_refresh_token(
    db: Session, old_rt: RefreshToken, user_id: int, email: str
) -> Tuple[str, str]:
    """Revoke an old refresh token and issue a new one.

    Args:
        db (Session): Database session.
        old_rt (RefreshToken): Existing refresh token to revoke.
        user_id (int): User ID.
        email (str): User email.

    Returns:
        Tuple[str, str]: New access token and new refresh token.
    """
    old_rt.revoked = True
    db.add(old_rt)

    new_info = create_refresh_token(subject=str(user_id), email=email)
    new_token = new_info["token"]
    new_jti = new_info["jti"]
    new_expires = new_info["expires_at"]

    new_rt = RefreshToken(
        jti=new_jti,
        token_hash=hash_token(new_token),
        user_id=user_id,
        expires_at=new_expires,
    )
    db.add(new_rt)

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    access_token = create_access_token(subject=str(user_id), email=email)
    return access_token, new_token


@router.post("/login")
def login(credentials: HTTPBasicCredentials = Depends(security)) -> Dict[str, str]:
    """Login a user and issue access and refresh tokens.

    Args:
        credentials (HTTPBasicCredentials): User email and password.

    Returns:
        dict: Access token, refresh token, and token type.
    """
    settings = ConfigMapper.get()
    email = credentials.username
    password = credentials.password

    with get_db(settings.database_uri) as db:
        user = db.query(User).filter(User.email == email).first()
        if not user or not verify_password(password, user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
            )

        access_token = create_access_token(
            subject=str(user.id), email=user.email, role=user.role
        )

        refresh_info = create_refresh_token(subject=str(user.id), email=user.email)
        _store_refresh_token(
            db,
            refresh_info["token"],
            user.id,
            refresh_info["jti"],
            refresh_info["expires_at"],
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_info["token"],
        "token_type": "bearer",
    }


@router.post("/refresh", response_model=TokenResponse)
def refresh(refresh_token: str) -> Dict[str, str]:
    """Refresh access and refresh tokens, rotating the old refresh token.

    Args:
        refresh_token (str): Raw refresh token.

    Returns:
        dict: New access token, refresh token, and token type.
    """
    settings = ConfigMapper.get()

    with get_db(settings.database_uri) as db:
        try:
            payload = decode_token(refresh_token)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token",
            )

        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong token type"
            )

        jti = payload.get("jti")
        user_id = int(payload.get("sub"))
        email = payload.get("email")

        old_rt = (
            db.query(RefreshToken)
            .filter(RefreshToken.jti == jti, RefreshToken.user_id == user_id)
            .first()
        )
        if not old_rt or old_rt.revoked:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Refresh token revoked or unknown",
            )

        if old_rt.token_hash != hash_token(refresh_token):
            old_rt.revoked = True
            db.add(old_rt)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Invalid refresh token"
            )

        access_token, new_refresh = _rotate_refresh_token(db, old_rt, user_id, email)

    return {
        "access_token": access_token,
        "refresh_token": new_refresh,
        "token_type": "bearer",
    }


@router.post("/revoke", status_code=200)
def revoke(jti: str = None, refresh_token: str = None) -> Dict[str, str]:
    """Revoke a refresh token by jti or raw refresh token.

    Args:
        jti (str, optional): Token unique identifier.
        refresh_token (str, optional): Raw refresh token.

    Returns:
        dict: Status message.
    """
    settings = ConfigMapper.get()

    with get_db(settings.database_uri) as db:
        if refresh_token:
            try:
                payload = decode_token(refresh_token)
                jti = payload.get("jti")
            except Exception:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid token provided",
                )

        if not jti:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Provide jti or refresh_token",
            )

        rt = db.query(RefreshToken).filter(RefreshToken.jti == jti).first()
        if not rt:
            return {"message": "Token not found or already revoked"}

        rt.revoked = True
        try:
            db.add(rt)
            db.commit()
        except Exception:
            db.rollback()
            raise

    return {"message": "Token revoked"}
