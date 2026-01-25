import uuid

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.analysis_repository import AnalysisRepository
from app.infra.artifacts.analysis_artifacts_repository import AnalysisArtifactsRepository


class AnalysisReadService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.analysis_repo = AnalysisRepository(db)

    async def get_meta(self, *, analysis_id: uuid.UUID, user_id: uuid.UUID) -> dict:
        row = await self.analysis_repo.get_accessible_by_id(analysis_id=analysis_id, user_id=user_id)
        if not row:
            raise HTTPException(status_code=404, detail="analysis not found")

        danger_count = 0
        is_threat = False

        threats = AnalysisArtifactsRepository.load_threat_report(str(analysis_id))
        if isinstance(threats, list):
            danger_count = len(threats)
            is_threat = danger_count > 0

        return {
            "analysis_id": str(row.analysis_id),
            "status": row.status,
            "filename": row.filename,
            "timestamp": row.timestamp.isoformat() if getattr(row, "timestamp", None) else None,
            "sha256": row.file_hash,
            "pipeline_version": row.pipeline_version,
            "danger_count": danger_count,
            "is_threat": is_threat,
        }
