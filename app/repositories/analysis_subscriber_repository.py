import uuid
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis_subscriber import AnalysisSubscriber


class AnalysisSubscriberRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get(self, *, analysis_id: uuid.UUID, user_id: uuid.UUID) -> Optional[AnalysisSubscriber]:
        result = await self.db.execute(
            select(AnalysisSubscriber)
            .where(
                AnalysisSubscriber.analysis_id == analysis_id,
                AnalysisSubscriber.user_id == user_id,
            )
            .limit(1)
        )
        return result.scalars().first()

    async def ensure_subscribed(self, *, analysis_id: uuid.UUID, user_id: uuid.UUID) -> None:
        existing = await self.get(analysis_id=analysis_id, user_id=user_id)
        if existing:
            return
        self.db.add(AnalysisSubscriber(analysis_id=analysis_id, user_id=user_id))
        await self.db.commit()
