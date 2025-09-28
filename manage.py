#!/usr/bin/env python3
import argparse

from sqlalchemy import text

from app.db import SessionLocal, engine
from app.models import Base, User
from app.utils.security import hash_password


def create_tables():
    Base.metadata.create_all(bind=engine)
    print("Tables created")


def drop_tables():
    Base.metadata.drop_all(bind=engine)
    print("Tables dropped")


def create_admin(email, password):
    session = SessionLocal()
    try:
        existing = session.query(User).filter(User.email == email).first()
        if existing:
            print("Admin already exists")
            return
        user = User(email=email, password=hash_password(password), is_admin=True)
        session.add(user)
        session.commit()
        print(f"Admin {email} created")
    finally:
        session.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cmd", choices=["create_db", "drop_db", "create_admin"])
    parser.add_argument("--email", help="Admin email (for create_admin)")
    parser.add_argument("--password", help="Admin password (for create_admin)")
    args = parser.parse_args()

    if args.cmd == "create_db":
        create_tables()
    elif args.cmd == "drop_db":
        drop_tables()
    elif args.cmd == "create_admin":
        if not args.email or not args.password:
            print("email and password required for create_admin")
            return
        create_admin(args.email, args.password)


if __name__ == "__main__":
    main()
