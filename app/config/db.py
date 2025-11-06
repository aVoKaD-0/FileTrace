import os
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

# Получаем строку подключения к базе данных из переменной окружения или используем значение по умолчанию
# Теперь мы используем host.docker.internal для обращения к хосту из контейнера
DATABASE_URL = os.getenv("DATABASE_URL", "")

# Преобразуем стандартную строку подключения к PostgreSQL в асинхронную для SQLAlchemy
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

# Создаем асинхронный движок SQLAlchemy с увеличенным таймаутом для Windows
engine = create_async_engine(
    DATABASE_URL, 
    echo=False,
    pool_pre_ping=True,
    pool_recycle=300,
    pool_size=5,
    max_overflow=10,
    connect_args={
        "command_timeout": 30  # Увеличиваем таймаут для Windows
    }
)

# Создаем фабрику сессий для получения сессий базы данных
AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)

# Функция для получения асинхронной сессии
async def get_async_session():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close() 