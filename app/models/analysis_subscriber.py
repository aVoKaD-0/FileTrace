import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, UUID, ForeignKey, Integer, TIMESTAMP, UniqueConstraint
from app.infra.db.base import Base


class AnalysisSubscriber(Base):
    __tablename__ = "analysis_subscribers"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(UUID(as_uuid=True), ForeignKey("analysis.analysis_id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    subscribed_at = Column(TIMESTAMP(timezone=True), default=datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        UniqueConstraint("analysis_id", "user_id", name="uq_analysis_subscribers_analysis_user"),
    )
