import uuid
from pydantic import BaseModel


class AnalysisRequest(BaseModel):
    analysis_id: uuid.UUID
    result_data: dict

class AnalysisResponse(BaseModel):
    analysis_id: str
    status: str
    file_activity: list
    docker_output: str


