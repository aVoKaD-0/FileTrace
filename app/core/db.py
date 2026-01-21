import os
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool

from app.core.settings import settings

DATABASE_URL = settings.DATABASE_URL

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

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
