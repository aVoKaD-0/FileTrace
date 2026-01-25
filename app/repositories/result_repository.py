import uuid
from typing import Any, Optional, Tuple

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis import Analysis
from app.models.result import Results


class ResultRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_analysis_id(self, analysis_id: uuid.UUID) -> Optional[Results]:
        result = await self.db.execute(select(Results).where(Results.analysis_id == analysis_id))
        return result.scalars().first()

    async def get_analysis(self, analysis_id: uuid.UUID) -> Optional[Analysis]:
        result = await self.db.execute(select(Analysis).where(Analysis.analysis_id == analysis_id))
        return result.scalars().first()

    async def create_empty(self, analysis_id: uuid.UUID) -> Results:
        result = Results(analysis_id=analysis_id, file_activity="", docker_output="", results="")
        self.db.add(result)
        await self.db.commit()
        return result

    async def append_docker_output(self, analysis_id: str, msg: str) -> None:
        result = await self.get_by_analysis_id(uuid.UUID(str(analysis_id)))
        if not result:
            return
        result.docker_output = (result.docker_output or "") + msg
        self.db.add(result)
        await self.db.commit()

    async def set_results(self, analysis_id: str, result_data: str) -> None:
        result = await self.get_by_analysis_id(uuid.UUID(str(analysis_id)))
        if not result:
            return
        result.results = result_data
        self.db.add(result)
        await self.db.commit()

    async def set_file_activity(self, analysis_id: str, history: str) -> None:
        result = await self.get_by_analysis_id(uuid.UUID(str(analysis_id)))
        if not result:
            return
        result.file_activity = history
        self.db.add(result)
        await self.db.commit()

    async def set_error(self, analysis_id: str, error_message: str) -> None:
        result = await self.get_by_analysis_id(uuid.UUID(str(analysis_id)))
        if not result:
            return
        result.docker_output = error_message
        result.file_activity = ""
        self.db.add(result)
        await self.db.commit()

    async def get_chunk_result(self, analysis_id: str, offset: int = 0, limit: int = 50) -> Tuple[Any, Any]:
        result = await self.db.execute(
            text(
                f"""
                SELECT jsonb_path_query_array(
                    file_activity,
                    '$.items[{offset} to {offset + limit - 1}]'
                )
                FROM results
                WHERE analysis_id = :analysis_id
                """
            ),
            {"analysis_id": analysis_id},
        )

        total = await self.db.execute(
            text("""SELECT jsonb_array_length(file_activity) FROM results WHERE analysis_id = :analysis_id"""),
            {"analysis_id": analysis_id},
        )
        return result.scalars().all(), total.scalars().first()
