from app.config.db import Base
from sqlalchemy import Column, Text, UUID, ForeignKey
from sqlalchemy.orm import relationship

class Results(Base):
    __tablename__ = "results"

    analysis_id = Column(UUID(as_uuid=True), ForeignKey('analysis.analysis_id', ondelete="CASCADE"), primary_key=True)
    file_activity = Column(Text)
    docker_output = Column(Text)
    results = Column(Text)

    analysis = relationship("Analysis", back_populates="result")