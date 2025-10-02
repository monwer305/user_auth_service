import threading
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool

# Global connection pool dictionary
_CONNECTION_POOL = {}
_POOL_LOCK = threading.Lock()


class DatabasePool:
    """Manages a SQLAlchemy database engine and session factory."""

    def __init__(
        self,
        database_url: str,
        pool_size: int = 5,
        max_overflow: int = 10,
        pool_recycle: int = 3600,
    ):
        """
        Args:
            database_url (str): Database connection URL.
            pool_size (int): Number of connections to keep in the pool.
            max_overflow (int): Max extra connections beyond pool_size.
            pool_recycle (int): Recycle connections older than this (seconds) to prevent timeout.
        """
        self.engine = create_engine(
            database_url,
            poolclass=QueuePool,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_pre_ping=True,
            pool_recycle=pool_recycle,
            future=True,
        )
        self.SessionLocal = sessionmaker(
            bind=self.engine, autoflush=False, autocommit=False
        )
        # Store in global pool dict
        _CONNECTION_POOL[database_url] = self


@contextmanager
def get_db(database_url: str):
    """
    Provide a database session with proper commit/rollback handling.

    Yields:
        Session: SQLAlchemy session
    """

    # Thread-safe pool creation
    if database_url not in _CONNECTION_POOL:
        with _POOL_LOCK:
            if database_url not in _CONNECTION_POOL:
                DatabasePool(database_url)

    db = _CONNECTION_POOL[database_url].SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
