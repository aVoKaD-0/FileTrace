import uuid
from typing import List, Optional, Sequence, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis import Analysis
from app.models.analysis_subscriber import AnalysisSubscriber


class AnalysisRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_global_active(self):
        result = await self.db.execute(
            select(Analysis.analysis_id, Analysis.status, Analysis.timestamp)
            .where(Analysis.status.in_(["queued", "running"]))
            .order_by(Analysis.timestamp.asc())
        )
        return result.all()

    async def list_user_analyses(self, user_id: uuid.UUID) -> Sequence[Tuple]:
        result = await self.db.execute(
            select(Analysis.timestamp, Analysis.filename, Analysis.status, Analysis.analysis_id)
            .outerjoin(AnalysisSubscriber, AnalysisSubscriber.analysis_id == Analysis.analysis_id)
            .where((Analysis.user_id == user_id) | (AnalysisSubscriber.user_id == user_id))
            .distinct(Analysis.analysis_id)
        )
        return result.all()

    async def get_accessible_by_id(self, *, analysis_id: uuid.UUID, user_id: uuid.UUID) -> Optional[Analysis]:
        result = await self.db.execute(
            select(Analysis)
            .outerjoin(AnalysisSubscriber, AnalysisSubscriber.analysis_id == Analysis.analysis_id)
            .where(
                (Analysis.analysis_id == analysis_id)
                & ((Analysis.user_id == user_id) | (AnalysisSubscriber.user_id == user_id))
            )
            .limit(1)
        )
        return result.scalars().first()

    async def get_by_id(self, analysis_id: uuid.UUID) -> Optional[Analysis]:
        result = await self.db.execute(select(Analysis).where(Analysis.analysis_id == analysis_id))
        return result.scalars().first()

    async def set_status(self, analysis_id: str, status: str) -> None:
        analysis = await self.get_by_id(uuid.UUID(str(analysis_id)))
        if not analysis:
            return
        analysis.status = status
        self.db.add(analysis)
        await self.db.commit()

    async def find_latest_completed_by_hash(self, *, file_hash: str, pipeline_version: str) -> Optional[Analysis]:
        result = await self.db.execute(
            select(Analysis)
            .where(
                Analysis.file_hash == file_hash,
                Analysis.pipeline_version == pipeline_version,
                Analysis.status == "completed",
            )
            .order_by(Analysis.timestamp.desc())
            .limit(1)
        )
        return result.scalars().first()

    async def find_active_by_hash(self, *, file_hash: str, pipeline_version: str) -> Optional[Analysis]:
        result = await self.db.execute(
            select(Analysis)
            .where(
                Analysis.file_hash == file_hash,
                Analysis.pipeline_version == pipeline_version,
                Analysis.status.in_(["queued", "running"]),
            )
            .order_by(Analysis.timestamp.desc())
            .limit(1)
        )
        return result.scalars().first()

    async def create(self, *, user_id: uuid.UUID, filename: str, status: str, analysis_id: uuid.UUID, file_hash: str = "", pipeline_version: str = "") -> Analysis:
        analysis = Analysis(
            user_id=user_id,
            filename=filename,
            status=status,
            analysis_id=analysis_id,
            file_hash=file_hash,
            pipeline_version=pipeline_version,
        )
        self.db.add(analysis)
        await self.db.commit()
        return analysis
