from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.audit import AuditEvent


class AuditRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, *, event_type: str, user_id: Optional[str], source_ip: Optional[str], user_agent: Optional[str], request_id: Optional[str], metadata: Optional[Dict[str, Any]] = None) -> AuditEvent:
        event = AuditEvent(
            event_type=event_type,
            user_id=user_id,
            source_ip=source_ip,
            user_agent=user_agent,
            request_id=request_id,
            metadata=metadata or {},
        )
        self.db.add(event)
        await self.db.commit()
        await self.db.refresh(event)
        return event
