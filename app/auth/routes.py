from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session

from app.auth.deps import get_db
from app.db import SessionLocal
from app.models import RefreshToken, User
from app.schemas import TokenResponse
from app.utils.jwt import create_access_token, create_refresh_token, decode_token
from app.utils.security import hash_token, verify_password

security = HTTPBasic()
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login")
def login(
    credentials: HTTPBasicCredentials = Depends(security), db: Session = Depends(get_db)
):
    """
    Login using HTTP Basic Auth (username/email and password in Authorization header)
    """
    email = credentials.username
    password = credentials.password

    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    # Create access token
    access_token = create_access_token(
        subject=str(user.id), email=user.email, role=user.role
    )

    # Create refresh token
    refresh_info = create_refresh_token(subject=str(user.id), email=user.email)
    refresh_token_str = refresh_info["token"]
    jti = refresh_info["jti"]
    expires_at = refresh_info["expires_at"]

    # Store hashed refresh token
    rt = RefreshToken(
        jti=jti,
        token_hash=hash_token(refresh_token_str),
        user_id=user.id,
        expires_at=expires_at,
    )
    db.add(rt)
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token_str,
        "token_type": "bearer",
    }


@router.post("/refresh", response_model=TokenResponse)
def refresh(refresh_token: str, db: Session = Depends(get_db)):
    # Decode token (raises if invalid/expired)
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

    # find token by jti and compare hash
    rt = (
        db.query(RefreshToken)
        .filter(RefreshToken.jti == jti, RefreshToken.user_id == user_id)
        .first()
    )
    if not rt or rt.revoked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Refresh token revoked or unknown",
        )

    # compare stored hash with incoming
    from app.utils.security import hash_token as _hash_token

    if rt.token_hash != _hash_token(refresh_token):
        # token mismatch (maybe token rotated or stolen)
        # revoke the stored token for safety
        rt.revoked = True
        db.add(rt)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid refresh token"
        )

    # rotate: revoke old refresh token and issue new one
    rt.revoked = True
    db.add(rt)

    # create new refresh token
    new_info = create_refresh_token(subject=str(user_id), email=payload.get("email"))
    new_token = new_info["token"]
    new_jti = new_info["jti"]
    new_expires = new_info["expires_at"]

    new_rt = RefreshToken(
        jti=new_jti,
        token_hash=_hash_token(new_token),
        user_id=user_id,
        expires_at=new_expires,
    )
    db.add(new_rt)
    db.commit()

    # new access token
    access = create_access_token(subject=str(user_id), email=payload.get("email"))

    return {"access_token": access, "refresh_token": new_token, "token_type": "bearer"}


@router.post("/revoke", status_code=200)
def revoke(jti: str = None, refresh_token: str = None, db: Session = Depends(get_db)):
    """
    Revoke a refresh token. Provide either the jti or the refresh_token raw string.
    Admin endpoints or user-initiated sign-out should call this.
    """
    from app.utils.security import hash_token as _hash_token

    if refresh_token:
        try:
            payload = decode_token(refresh_token)
            jti = payload.get("jti")
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token provided"
            )

    if not jti:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide jti or refresh_token",
        )

    rt = db.query(RefreshToken).filter(RefreshToken.jti == jti).first()
    if not rt:
        # idempotent
        return {"message": "Token not found or already revoked"}

    rt.revoked = True
    db.add(rt)
    db.commit()
    return {"message": "Token revoked"}
