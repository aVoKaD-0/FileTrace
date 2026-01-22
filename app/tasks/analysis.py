import asyncio
import time

import redis

from app.core.settings import settings
from app.infra.redis_semaphore import acquire_semaphore_slot, refresh_semaphore_slot, release_semaphore_slot
from app.services.analysis_service import AnalysisService


def register_tasks(celery_app):
    @celery_app.task(name="analyze_file")
    def analyze_file_task(filename: str, analysis_id: str, user_id: str, file_hash: str, pipeline_version: str):
        r = redis.Redis.from_url(settings.REDIS_URL, decode_responses=False)
        limit = int(getattr(settings, "MAX_CONCURRENT_ANALYSES", 1) or 1)
        if limit < 1:
            limit = 1
        token = None
        slot_ttl_seconds = 60 * 30

        async def run_analysis():
            service = AnalysisService(
                filename=filename,
                analysis_id=analysis_id,
                uuid=user_id,
                file_hash=file_hash,
                pipeline_version=pipeline_version,
            )
            try:
                return await service.analyze()
            finally:
                pass

        try:
            token = acquire_semaphore_slot(r, limit=limit, ttl_seconds=slot_ttl_seconds, poll_seconds=1.0)

            stop_refresh = False

            def _keepalive():
                while not stop_refresh:
                    refresh_semaphore_slot(r, token, ttl_seconds=slot_ttl_seconds)
                    time.sleep(60)

            import threading

            t = threading.Thread(target=_keepalive, daemon=True)
            t.start()
            try:
                return asyncio.run(run_analysis())
            finally:
                stop_refresh = True
        finally:
            if token:
                release_semaphore_slot(r, token)

    return analyze_file_task
