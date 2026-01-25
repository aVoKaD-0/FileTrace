import uuid
from datetime import datetime
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from app.infra.db.base import Base
from sqlalchemy import Column, String, VARCHAR, Boolean, DateTime, Integer, Text
from sqlalchemy.orm import relationship

class Users(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_hash = Column(String(64), unique=True, index=True)
    email_encrypted = Column(Text)
    hashed_password = Column(VARCHAR(255))
    confirmed = Column(Boolean, default=False)
    confirmation_code = Column(String, nullable=True)
    refresh_token = Column(String, nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    login_attempts = Column(Integer, default=0)
    analyses = relationship("Analysis", back_populates="user", cascade="all, delete-orphan")