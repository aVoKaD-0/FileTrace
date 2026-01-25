import json
import logging

from app.infra.db.session import AsyncSessionLocal
from app.repositories.analysis_repository import AnalysisRepository
from app.repositories.result_repository import ResultRepository
from app.utils.websocket_manager import manager
from app.utils.analysis_log_filter import should_suppress, sanitize_line


class AnalysisStatusService:
    @staticmethod
    async def analysis_log(msg, analysis_id):
        logger = logging.getLogger("app")
        try:
            msg = str(msg)
            if should_suppress(msg):
                return

            msg = sanitize_line(msg)

            try:
                async with AsyncSessionLocal() as db:
                    await ResultRepository(db).append_docker_output(str(analysis_id), msg + "\n")
            except Exception:
                logger.exception("Failed to append analysis log to DB")

            try:
                await manager.send_message(
                    analysis_id,
                    json.dumps(
                        {
                            "event": "docker_log",
                            "message": msg,
                        }
                    ),
                )
            except Exception:
                logger.exception("Failed to send analysis log via websocket")
        except Exception:
            logger.exception("AnalysisStatusService.analysis_log failed")
            return

    @staticmethod
    async def save_result(analysis_id, result_data):
        async with AsyncSessionLocal() as db:
            await ResultRepository(db).set_results(str(analysis_id), result_data)

    @staticmethod
    async def save_file_activity(analysis_id, history):
        async with AsyncSessionLocal() as db:
            await AnalysisRepository(db).set_status(str(analysis_id), "completed")
            await ResultRepository(db).set_file_activity(str(analysis_id), history)

    @staticmethod
    async def update_analysis_status(analysis_id, status: str):
        async with AsyncSessionLocal() as db:
            await AnalysisRepository(db).set_status(str(analysis_id), status)

    @staticmethod
    async def update_history_on_error(analysis_id, error_message):
        async with AsyncSessionLocal() as db:
            await AnalysisRepository(db).set_status(str(analysis_id), "error")
            await ResultRepository(db).set_error(str(analysis_id), error_message)
