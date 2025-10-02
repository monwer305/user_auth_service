from config_utils import ConfigMapper
from sqlalchemy.exc import IntegrityError

from app.config_utils import ConfigMapper
from app.db import get_db
from app.models import Base, User
from app.utils.security import hash_password


def create_tables():
    """
    Creates all database tables defined in SQLAlchemy models.

    This function initializes the database schema by creating tables
    based on the metadata of the SQLAlchemy Base models.

    Raises:
        SQLAlchemyError: If table creation fails.
    """
    from app.db import _CONNECTION_POOL, _get_database_url

    database_url = _get_database_url()
    engine = _CONNECTION_POOL[database_url].engine
    Base.metadata.create_all(bind=engine)
    print("[Bootstrap] Tables created successfully.")


def create_superadmin():
    """
    Creates a superadmin user if one does not already exist.

    Checks for an existing superadmin by email. If not found, creates a new superadmin user
    with credentials from configuration settings. Handles database integrity errors and ensures
    session closure.

    Raises:
        IntegrityError: If a database integrity constraint is violated.
    """

    settings = ConfigMapper.get()
    with get_db(settings.database_uri) as db:  # ensures proper commit/rollback/close
        existing = (
            db.query(User).filter(User.email == settings.SUPER_ADMIN_EMAIL).first()
        )
        if existing:
            print(
                f"[Bootstrap] Superadmin '{settings.SUPER_ADMIN_EMAIL}' already exists."
            )
            return

        superadmin = User(
            email=settings.SUPER_ADMIN_EMAIL,
            password=hash_password(settings.SUPER_ADMIN_PASSWORD),
            role="superadmin",
            is_active=True,
            disabled=False,
        )
        try:
            db.add(superadmin)
            db.commit()
            print(
                f"[Bootstrap] Superadmin '{settings.SUPER_ADMIN_EMAIL}' created successfully."
            )
        except IntegrityError as e:
            db.rollback()
            print(f"[Bootstrap] IntegrityError creating superadmin: {e}")


def bootstrap():
    """
    Runs the full bootstrap process.

    Creates database tables, superadmin user, and prints status messages.
    """
    print("[Bootstrap] Starting bootstrap process...")
    create_tables()
    create_superadmin()
    print("[Bootstrap] Bootstrap process complete.")
