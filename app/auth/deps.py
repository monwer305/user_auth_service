from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import RefreshToken, User
from app.utils.jwt import decode_token

bearer_scheme = HTTPBearer()


def require_role(required: str):
    """
    Dependency to enforce role.
    required can be 'admin' or 'superadmin'.
    """

    def wrapper(user: User = Depends(get_current_user)):
        if required == "admin" and user.role not in ["admin", "superadmin"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required"
            )
        if required == "superadmin" and user.role != "superadmin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Superadmin required"
            )
        return user

    return wrapper


def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
):
    token = credentials.credentials
    try:
        payload = decode_token(token)
    except Exception as exc:
        print(str(exc))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect token type"
        )

    user_id = int(payload.get("sub"))
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    return user
