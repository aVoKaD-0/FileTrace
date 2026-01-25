from app.infra.db.base import Base
from sqlalchemy import Column, Text, UUID, ForeignKey, Integer, TIMESTAMP, String
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

class Analysis(Base):
    __tablename__ = "analysis"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    filename = Column(Text)
    file_hash = Column(String(64), index=True)
    pipeline_version = Column(String(32), index=True)
    timestamp = Column(TIMESTAMP(timezone=True), default=datetime.now(timezone.utc))
    status = Column(Text)
    analysis_id = Column(UUID(as_uuid=True), unique=True)

    user = relationship("Users", foreign_keys=[user_id], back_populates="analyses")

    result = relationship("Results", back_populates="analysis", uselist=False)