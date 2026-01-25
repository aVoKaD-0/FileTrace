import os

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.settings import settings


def _normalize_database_url(url: str) -> str:
    if not url:
        return url
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


DATABASE_URL = _normalize_database_url(settings.DATABASE_URL)

_engine_kwargs = {
    "echo": False,
    "pool_pre_ping": True,
    "connect_args": {
        "command_timeout": 30,
    },
}

if os.name == "nt":
    _engine_kwargs.update(
        {
            "poolclass": NullPool,
        }
    )
else:
    _engine_kwargs.update(
        {
            "pool_recycle": 300,
            "pool_size": 5,
            "max_overflow": 10,
        }
    )

engine = create_async_engine(DATABASE_URL, **_engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)