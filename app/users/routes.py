from typing import Dict, List

from fastapi import APIRouter, HTTPException, status

from app.auth.deps import get_current_user, require_role
from app.config_utils import ConfigMapper
from app.db import get_db
from app.models import User
from app.schemas import UserCreate, UserOut, UserUpdate
from app.utils.jwt import create_reset_token, decode_token
from app.utils.notify import send_email
from app.utils.security import hash_password

router = APIRouter(prefix="/users", tags=["users"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate) -> UserOut:
    """Register a new user with default role 'user'.

    Args:
        user_in (UserCreate): User input data.

    Returns:
        UserOut: Newly created user.
    """
    settings = ConfigMapper.get()
    with get_db(settings.database_uri) as db:
        existing = db.query(User).filter(User.email == user_in.email).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="User already exists"
            )

        user = User(
            email=user_in.email, password=hash_password(user_in.password), role="user"
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return user


@router.get("/me", response_model=UserOut)
def me(current_user: User = get_current_user()) -> UserOut:
    """Return the current logged-in user.

    Returns:
        UserOut: Current user.
    """
    return current_user


@router.delete("/me")
def delete_me(current_user: User = get_current_user()) -> Dict[str, str]:
    """Delete the current user's account (regular users only).

    Returns:
        dict: Status message.
    """
    if current_user.role in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admins cannot self-delete")

    settings = ConfigMapper.get()
    with get_db(settings.database_uri) as db:
        db.delete(current_user)
        db.commit()
    return {"message": "User deleted"}


@router.get("/", response_model=List[UserOut])
def list_users(admin: User = require_role("admin")) -> List[UserOut]:
    """List all users (admin only).

    Returns:
        list[UserOut]: All users.
    """
    settings = ConfigMapper.get()
    with get_db(settings.database_uri) as db:
        users = db.query(User).all()
    return users


@router.post("/create", response_model=UserOut)
def create_user_as_admin(
    user_in: UserCreate, admin: User = require_role("admin")
) -> UserOut:
    """Create a new user (admin only, can assign role).

    Args:
        user_in (UserCreate): User input data.

    Returns:
        UserOut: Newly created user.
    """
    settings = ConfigMapper.get()
    with get_db(settings.database_uri) as db:
        if db.query(User).filter(User.email == user_in.email).first():
            raise HTTPException(status_code=409, detail="User exists")
        user = User(
            email=user_in.email,
            password=hash_password(user_in.password),
            role=user_in.role,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return user


@router.patch("/{user_id}/disable")
def disable_user(user_id: int, admin: User = require_role("admin")) -> Dict[str, str]:
    """Disable a user account (admin only, cannot disable admins/superadmins).

    Returns:
        dict: Status message.
    """
    settings = ConfigMapper.get()
    with get_db(settings.database_uri) as db:
        target = db.query(User).filter(User.id == user_id).first()
        if not target:
            raise HTTPException(404, detail="User not found")
        if target.role in ["admin", "superadmin"]:
            raise HTTPException(403, detail="Cannot disable admin or superadmin")
        target.disabled = True
        db.commit()
    return {"message": "User disabled"}


@router.delete("/{user_id}")
def delete_user(user_id: int, admin: User = require_role("admin")) -> Dict[str, str]:
    """Delete a user (admin only, cannot delete admins/superadmins).

    Returns:
        dict: Status message.
    """
    settings = ConfigMapper.get()
    with get_db(settings.database_uri) as db:
        target = db.query(User).filter(User.id == user_id).first()
        if not target:
            raise HTTPException(404, detail="User not found")
        if target.role in ["admin", "superadmin"]:
            raise HTTPException(403, detail="Cannot delete admin or superadmin")
        db.delete(target)
        db.commit()
    return {"message": "User deleted"}


@router.put("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def update_user(
    user_id: int, update_data: UserUpdate, current_user: User = get_current_user()
) -> UserOut:
    """Update user info.

    Rules:
        - Users can only update themselves.
        - Admins cannot update admins/superadmins.
        - Only superadmins can change roles.

    Returns:
        UserOut: Updated user.
    """
    settings = ConfigMapper.get()
    with get_db(settings.database_uri) as db:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        if current_user.role == "user" and current_user.id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed"
            )
        if current_user.role == "admin" and user.role in ["admin", "superadmin"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not allowed to update admins or superadmin",
            )

        if update_data.email:
            user.email = update_data.email
        if update_data.password:
            user.password = hash_password(update_data.password)
        if update_data.role and current_user.role == "superadmin":
            user.role = update_data.role
        if update_data.is_active is not None and current_user.role in [
            "admin",
            "superadmin",
        ]:
            user.is_active = update_data.is_active

        db.commit()
        db.refresh(user)
    return user


@router.post("/forgot-password")
def forgot_password(email: str) -> Dict[str, str]:
    """Generate password reset token and send email (generic response).

    Args:
        email (str): User email.

    Returns:
        dict: Status message.
    """
    settings = ConfigMapper.get()
    with get_db(settings.database_uri) as db:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return {"message": "If the user exists, a reset email will be sent"}

        token = create_reset_token(subject=str(user.id), email=user.email)
        reset_link = f"https://frontend-app/reset-password?token={token}"

        subject = "Password Reset Request"
        body = f"""
        <p>Hello {user.email},</p>
        <p>You requested a password reset. Click the link below to reset your password:</p>
        <p><a href="{reset_link}">Reset Password</a></p>
        <p>This link will expire in 30 minutes.</p>
        """
        send_email(user.email, subject, body)

    return {"message": "If the user exists, a reset email will be sent"}


@router.post("/reset-password")
def reset_password(token: str, new_password: str) -> Dict[str, str]:
    """Reset user password using reset token.

    Args:
        token (str): Reset token.
        new_password (str): New password.

    Returns:
        dict: Status message.
    """
    settings = ConfigMapper.get()
    with get_db(settings.database_uri) as db:
        try:
            payload = decode_token(token)
        except Exception:
            raise HTTPException(400, detail="Invalid or expired reset token")

        if payload.get("type") != "reset":
            raise HTTPException(400, detail="Invalid token type")

        user = db.query(User).filter(User.id == int(payload.get("sub"))).first()
        if not user:
            raise HTTPException(404, detail="User not found")

        user.password = hash_password(new_password)
        db.commit()
    return {"message": "Password reset successful"}
