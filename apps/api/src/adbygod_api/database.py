"""
AdByG0d Platform — Database Engine (async)
Uses SQLAlchemy 2.0 async engine with asyncpg for non-blocking I/O.
"""

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from adbygod_api.config import settings


def _async_url(url: str) -> str:
    """Convert a standard postgresql:// DSN to the asyncpg variant."""
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


# Engine creation with conditional parameters (SQLite doesn't support pooling)
url = _async_url(settings.DATABASE_URL)
engine_kwargs = {
    "pool_pre_ping": True,
    "echo": settings.SQL_ECHO,
}

if not url.startswith("sqlite"):
    engine_kwargs.update({
        "pool_size": 20,
        "max_overflow": 40,
        "pool_timeout": 30,
        "pool_recycle": 1800,
    })

engine = create_async_engine(url, **engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    # disable autoflush so multi-step transactions aren't
    # prematurely flushed to the DB before we explicitly commit.
    autoflush=False,
)

Base = declarative_base()


async def get_db():
    """Async dependency-injection for database sessions."""
    async with AsyncSessionLocal() as session:
        yield session
