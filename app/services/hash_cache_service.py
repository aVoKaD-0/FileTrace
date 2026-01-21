import hashlib
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.settings import settings
from app.models.analysis import Analysis
from app.services.user_service import UserService


class HashCacheService:
    @staticmethod
    async def calculate_hash(file_content: bytes) -> str:
        return hashlib.sha256(file_content).hexdigest()

    @staticmethod
    async def get_cached_completed(db: AsyncSession, file_hash: str, pipeline_version: Optional[str] = None) -> Optional[Analysis]:
        version = pipeline_version or settings.PIPELINE_VERSION
        return await UserService(db).find_latest_completed_by_hash(file_hash=file_hash, pipeline_version=version)

    @staticmethod
    async def get_active_run(db: AsyncSession, file_hash: str, pipeline_version: Optional[str] = None) -> Optional[Analysis]:
        version = pipeline_version or settings.PIPELINE_VERSION
        return await UserService(db).find_active_by_hash(file_hash=file_hash, pipeline_version=version)
