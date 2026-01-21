import asyncio
import os
import time
import uuid

from celery import Celery
import redis

from app.core.db import engine
from app.core.settings import settings
from app.services.analysis_service import AnalysisService


celery_app = Celery(
    "filetrace",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

if os.name == "nt":
    celery_app.conf.update(
        worker_pool="threads",
    )


_SEMAPHORE_KEY = "filetrace:analysis_semaphore"
_SEMAPHORE_TOKEN_KEY_PREFIX = "filetrace:analysis_semaphore:token:"


def _acquire_semaphore_slot(r: redis.Redis, *, limit: int, ttl_seconds: int, poll_seconds: float = 1.0) -> str:
    """Distributed semaphore implemented as a ZSET with expirations.

    - members: token strings
    - score: unix timestamp when the token expires
    """
    token = uuid.uuid4().hex

    lua = r.register_script(
        """
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local limit = tonumber(ARGV[2])
        local ttl = tonumber(ARGV[3])
        local token = ARGV[4]
        local token_prefix = ARGV[5]

        -- cleanup expired
        redis.call('ZREMRANGEBYSCORE', key, '-inf', now)

        -- cleanup orphan tokens (leftovers from crashed/restarted workers)
        local members = redis.call('ZRANGE', key, 0, -1)
        for i = 1, #members do
            local t = members[i]
            local tok_key = token_prefix .. t
            if redis.call('EXISTS', tok_key) == 0 then
                redis.call('ZREM', key, t)
            end
        end

        local count = redis.call('ZCARD', key)
        if count < limit then
            redis.call('ZADD', key, now + ttl, token)
            redis.call('SET', token_prefix .. token, '1', 'EX', ttl)
            return token
        end
        return ''
        """
    )

    while True:
        now = time.time()
        acquired = lua(keys=[_SEMAPHORE_KEY], args=[now, int(limit), int(ttl_seconds), token, _SEMAPHORE_TOKEN_KEY_PREFIX])
        if acquired:
            try:
                acquired_str = acquired.decode("utf-8") if isinstance(acquired, (bytes, bytearray)) else str(acquired)
            except Exception:
                acquired_str = str(acquired)
            if acquired_str:
                return acquired_str
        time.sleep(poll_seconds)


def _release_semaphore_slot(r: redis.Redis, token: str) -> None:
    try:
        r.zrem(_SEMAPHORE_KEY, token)
        r.delete(_SEMAPHORE_TOKEN_KEY_PREFIX + token)
    except Exception:
        pass


def _refresh_semaphore_slot(r: redis.Redis, token: str, *, ttl_seconds: int) -> None:
    """Extend semaphore slot lifetime for long-running analyses."""
    try:
        now = time.time()
        r.zadd(_SEMAPHORE_KEY, {token: now + int(ttl_seconds)})
        r.expire(_SEMAPHORE_TOKEN_KEY_PREFIX + token, int(ttl_seconds))
    except Exception:
        pass


@celery_app.task(name="analyze_file")
def analyze_file_task(filename: str, analysis_id: str, user_id: str, file_hash: str, pipeline_version: str):
    r = redis.Redis.from_url(settings.REDIS_URL, decode_responses=False)
    limit = int(getattr(settings, "MAX_CONCURRENT_ANALYSES", 1) or 1)
    if limit < 1:
        limit = 1
    token = None
    slot_ttl_seconds = 60 * 30

    async def run_analysis():
        service = AnalysisService(filename=filename, analysis_id=analysis_id, uuid=user_id, file_hash=file_hash, pipeline_version=pipeline_version)
        try:
            return await service.analyze()
        finally:
            pass

    try:
        token = _acquire_semaphore_slot(r, limit=limit, ttl_seconds=slot_ttl_seconds, poll_seconds=1.0)

        stop_refresh = False

        def _keepalive():
            while not stop_refresh:
                _refresh_semaphore_slot(r, token, ttl_seconds=slot_ttl_seconds)
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
            _release_semaphore_slot(r, token)
