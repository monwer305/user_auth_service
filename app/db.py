from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from app.config import settings

# SQLAlchemy connection string for MySQL via PyMySQL
DATABASE_URL = (
    f"mysql+pymysql://{settings.MYSQL_USER}:{settings.MYSQL_PASSWORD}"
    f"@{settings.MYSQL_HOST}:{settings.MYSQL_PORT}/{settings.MYSQL_DB}"
)

# Use a sync engine and scoped sessions (simple and safe for many use cases)
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)

SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))
