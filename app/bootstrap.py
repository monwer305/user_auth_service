import os

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import SessionLocal, engine
from app.models import Base, User
from app.utils.security import hash_password

# Environment variables for superadmin
SUPERADMIN_EMAIL = os.getenv("SUPERADMIN_EMAIL", "superadmin@example.com")
SUPERADMIN_PASSWORD = os.getenv("SUPERADMIN_PASSWORD", "SuperStrongPassword!")

# Optional sample users
SAMPLE_USERS = [
    {"email": "admin@example.com", "password": "AdminPassword!", "role": "admin"},
    {"email": "user1@example.com", "password": "UserPassword!", "role": "user"},
]


def create_tables():
    """Create all tables based on SQLAlchemy models."""
    Base.metadata.create_all(bind=engine)
    print("[Bootstrap] Tables created successfully.")


def create_superadmin():
    """Create superadmin user if it does not exist."""
    session: Session = SessionLocal()
    try:
        existing = session.query(User).filter(User.email == SUPERADMIN_EMAIL).first()
        if existing:
            print(f"[Bootstrap] Superadmin '{SUPERADMIN_EMAIL}' already exists.")
        else:
            superadmin = User(
                email=SUPERADMIN_EMAIL,
                password=hash_password(SUPERADMIN_PASSWORD),
                role="superadmin",
                is_active=True,
                disabled=False,
            )
            session.add(superadmin)
            session.commit()
            print(f"[Bootstrap] Superadmin '{SUPERADMIN_EMAIL}' created successfully.")
    except IntegrityError as e:
        session.rollback()
        print(f"[Bootstrap] IntegrityError: {e}")
    finally:
        session.close()


def create_sample_users():
    """Create sample admin/user accounts (idempotent)."""
    session: Session = SessionLocal()
    try:
        for u in SAMPLE_USERS:
            existing = session.query(User).filter(User.email == u["email"]).first()
            if existing:
                print(f"[Bootstrap] User '{u['email']}' already exists.")
                continue
            user = User(
                email=u["email"],
                password=hash_password(u["password"]),
                role=u["role"],
                is_active=True,
                disabled=False,
            )
            session.add(user)
        session.commit()
        print("[Bootstrap] Sample users created/verified successfully.")
    except IntegrityError as e:
        session.rollback()
        print(f"[Bootstrap] IntegrityError: {e}")
    finally:
        session.close()


def bootstrap():
    """Run full bootstrap: tables + superadmin + sample users."""
    print("[Bootstrap] Starting bootstrap process...")
    create_tables()
    create_superadmin()
    create_sample_users()
    print("[Bootstrap] Bootstrap process complete.")
