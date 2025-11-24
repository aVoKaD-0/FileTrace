import uuid
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy import Column, String, DateTime, Text, ForeignKey
from app.config.db import Base


class AuditEvent(Base):
    __tablename__ = "auditevents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    occurred_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    event_type = Column(String(64), nullable=False)
    source_ip = Column(Text)
    user_agent = Column(Text)
    request_id = Column(String(64))
    metadatas = Column(JSONB)
