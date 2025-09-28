from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth.deps import get_current_user, get_db, require_role
from app.models import User
from app.schemas import UserCreate, UserOut, UserUpdate
from app.utils.jwt import create_reset_token, decode_token
from app.utils.notify import send_email
from app.utils.security import hash_password, verify_password

router = APIRouter(prefix="/users", tags=["users"])

# --- Regular user endpoints ---


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
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
def me(current_user: User = Depends(get_current_user)):
    return current_user


@router.delete("/me", status_code=200)
def delete_me(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    if current_user.role in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admins cannot self-delete")
    db.delete(current_user)
    db.commit()
    return {"message": "User deleted"}


# --- Admin endpoints ---


@router.get("/", response_model=List[UserOut])
def list_users(
    admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)
):
    return db.query(User).all()


@router.post("/create", response_model=UserOut)
def create_user_as_admin(
    user_in: UserCreate,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    if db.query(User).filter(User.email == user_in.email).first():
        raise HTTPException(status_code=409, detail="User exists")
    user = User(
        email=user_in.email, password=hash_password(user_in.password), role=user_in.role
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.patch("/{user_id}/disable")
def disable_user(
    user_id: int,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(404, detail="User not found")
    if target.role in ["admin", "superadmin"]:
        raise HTTPException(403, detail="Cannot disable admin or superadmin")
    target.disabled = True
    db.commit()
    return {"message": "User disabled"}


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
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
    user_id: int,
    update_data: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Role-based rules
    if current_user.role == "user":
        if current_user.id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed"
            )
    elif current_user.role == "admin":
        if user.role in ["admin", "superadmin"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not allowed to update admins or superadmin",
            )

    # Apply updates
    if update_data.email:
        user.email = update_data.email
    if update_data.password:
        user.password = hash_password(update_data.password)
    if update_data.role and current_user.role == "superadmin":
        # only superadmin can change roles
        user.role = update_data.role
    if update_data.is_active is not None:
        if current_user.role in ["admin", "superadmin"]:
            user.is_active = update_data.is_active

    db.commit()
    db.refresh(user)

    return user


# --- Forgot / Reset password ---


@router.post("/forgot-password")
def forgot_password(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return {
            "message": "If the user exists, a reset email will be sent"
        }  # prevent info leak

    token = create_reset_token(subject=str(user.id), email=user.email)
    reset_link = f"https://frontend-app/reset-password?token={token}"

    # Send email
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
def reset_password(token: str, new_password: str, db: Session = Depends(get_db)):
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
