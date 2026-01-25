import math
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.settings import settings
from app.repositories.analysis_repository import AnalysisRepository
from app.services.user_service import UserService


class AnalysisWsService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.userservice = UserService(db)
        self.analysis_repo = AnalysisRepository(db)

    async def get_analysis_snapshot(self, analysis_id: str) -> Dict[str, Any]:
        return await self.userservice.get_result_data(str(analysis_id))

    async def get_history_payload(self, *, user_id: uuid.UUID) -> Dict[str, Any]:
        rows = await self.userservice.get_user_analyses(user_id)

        history: List[Dict[str, Any]] = []
        for row in rows:
            ts = getattr(row, "timestamp", None) or row[0]
            history.append(
                {
                    "timestamp": ts.isoformat() if ts else None,
                    "filename": getattr(row, "filename", None) or row[1],
                    "status": getattr(row, "status", None) or row[2],
                    "analysis_id": str(getattr(row, "analysis_id", None) or row[3]),
                }
            )

        global_active_rows = await self.analysis_repo.list_global_active()

        active_total = len(global_active_rows)
        max_conc = max(int(getattr(settings, "MAX_CONCURRENT_ANALYSES", 1) or 1), 1)

        positions: Dict[str, Dict[str, Any]] = {}
        for idx, (aid, st, ts) in enumerate(global_active_rows):
            ahead = idx
            eta_minutes = int(3 * math.ceil(ahead / max_conc)) if ahead > 0 else 0
            positions[str(aid)] = {
                "active_position": idx + 1,
                "active_total": active_total,
                "ahead": ahead,
                "eta_minutes": eta_minutes,
            }

        for item in history:
            if item.get("status") in ("queued", "running"):
                q = positions.get(item["analysis_id"])
                if q:
                    item.update(q)

        return {"event": "history", "history": history}
