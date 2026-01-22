import asyncio
import os
import shutil
import time
import uuid

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import redis
from sqlalchemy import select

from app.core.settings import settings
from app.core.db import AsyncSessionLocal
from app.infra.redis_semaphore import acquire_semaphore_slot, refresh_semaphore_slot, release_semaphore_slot
from app.models.analysis import Analysis
from app.models.result import Results
from app.repositories.analysis_artifacts_repository import AnalysisArtifactsRepository
from app.services.analysis_service import AnalysisService
from app.services.user_service import UserService
from app.utils.file_operations import FileOperations


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


def _download_stream(url: str, *, timeout_s: int, max_bytes: int) -> bytes:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) FileTrace/1.0",
        "Accept": "*/*",
        "Connection": "close",
    }

    s = requests.Session()
    retry = Retry(
        total=2,
        connect=2,
        read=2,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))

    timeout = (min(10, timeout_s), timeout_s)

    with s.get(url, stream=True, timeout=timeout, headers=headers, allow_redirects=True) as r:
        r.raise_for_status()

        cl = r.headers.get("Content-Length") or r.headers.get("content-length")
        if str(cl or "").isdigit() and max_bytes > 0 and int(cl) > max_bytes:
            raise RuntimeError("Слишком большой файл по ссылке")

        buf = bytearray()
        for chunk in r.iter_content(chunk_size=1024 * 256):
            if not chunk:
                continue
            buf.extend(chunk)
            if len(buf) > max_bytes:
                raise RuntimeError("Слишком большой файл по ссылке")
            if len(buf) >= 2 and buf[0:2] != b"MZ":
                raise RuntimeError("Файл по ссылке не похож на Windows PE (.exe)")
        return bytes(buf)


def _copy_artifacts(src_analysis_id: str, dst_analysis_id: str) -> None:
    try:
        src_dir = AnalysisArtifactsRepository.get_base_dir(src_analysis_id)
        dst_dir = AnalysisArtifactsRepository.get_base_dir(dst_analysis_id)
        os.makedirs(dst_dir, exist_ok=True)

        filenames = [
            "trace.csv",
            "trace.etl",
            "trace.json",
            "clean_tree.csv",
            "clean_tree.json",
            "threat_report.json",
        ]

        for name in filenames:
            src = os.path.join(src_dir, name)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(dst_dir, name))
    except Exception:
        # Best-effort: artifacts are optional and may not exist
        return


def register_url_tasks(celery_app, analyze_file_task):
    @celery_app.task(name="download_url_and_enqueue_analysis")
    def download_url_and_enqueue_analysis_task(url: str, analysis_id: str, user_id: str, filename: str, pipeline_version: str):
        async def _run():
            db = AsyncSessionLocal()
            try:
                userservice = UserService(db)
                analysis_uuid = uuid.UUID(str(analysis_id))
                user_uuid = uuid.UUID(str(user_id))

                async def _set_error(message: str) -> None:
                    analysis_res = await db.execute(select(Analysis).where(Analysis.analysis_id == analysis_uuid).limit(1))
                    analysis = analysis_res.scalars().first()
                    result = await db.get(Results, analysis_uuid)
                    if analysis and result:
                        analysis.status = "error"
                        result.docker_output = message
                        result.file_activity = ""
                        result.results = ""
                        await db.commit()

                try:
                    timeout_s = int(getattr(settings, "URL_DOWNLOAD_TIMEOUT_SECONDS", 30) or 30)
                    max_bytes = int(getattr(settings, "URL_MAX_DOWNLOAD_BYTES", 50 * 1024 * 1024) or 50 * 1024 * 1024)
                    content = _download_stream(url, timeout_s=timeout_s, max_bytes=max_bytes)
                except Exception as e:
                    await _set_error(str(e))
                    return

                import hashlib

                file_hash = hashlib.sha256(content).hexdigest()

                # If there is an active analysis with the same hash, do NOT start a second one.
                # Wait for it to finish, then copy results+artifacts into this analysis_id so UI works.
                active = await userservice.find_active_by_hash(file_hash=file_hash, pipeline_version=pipeline_version)
                if active:
                    await userservice.subscribe_user_to_analysis(analysis_id=active.analysis_id, user_id=user_uuid)

                    analysis_res = await db.execute(select(Analysis).where(Analysis.analysis_id == analysis_uuid).limit(1))
                    analysis = analysis_res.scalars().first()
                    if analysis:
                        analysis.filename = filename
                        analysis.file_hash = file_hash
                        analysis.pipeline_version = pipeline_version
                        analysis.status = active.status
                        await db.commit()

                    # Poll until the active analysis finishes (best-effort)
                    for _ in range(360):  # up to ~30 minutes
                        await db.refresh(active)
                        if active.status in {"completed", "error"}:
                            break
                        await asyncio.sleep(5)

                    if active.status == "completed":
                        cached_result = await db.get(Results, active.analysis_id)
                        current_result = await db.get(Results, analysis_uuid)
                        current_analysis_res = await db.execute(select(Analysis).where(Analysis.analysis_id == analysis_uuid).limit(1))
                        current_analysis = current_analysis_res.scalars().first()
                        if current_analysis:
                            current_analysis.status = "completed"
                            current_analysis.file_hash = file_hash
                            current_analysis.pipeline_version = pipeline_version
                            current_analysis.filename = filename

                        if cached_result and current_result:
                            current_result.file_activity = cached_result.file_activity
                            current_result.docker_output = cached_result.docker_output
                            current_result.results = cached_result.results

                        await db.commit()
                        _copy_artifacts(str(active.analysis_id), str(analysis_uuid))
                        return

                    await _set_error("Анализ с таким же файлом завершился с ошибкой")
                    return

                # Cache shortcut: if same hash already completed, copy cached results into current analysis
                cached = await userservice.find_latest_completed_by_hash(file_hash=file_hash, pipeline_version=pipeline_version)
                if cached:
                    await userservice.subscribe_user_to_analysis(analysis_id=cached.analysis_id, user_id=user_uuid)

                    cached_result = await db.get(Results, cached.analysis_id)
                    current_result = await db.get(Results, analysis_uuid)
                    current_analysis_res = await db.execute(select(Analysis).where(Analysis.analysis_id == analysis_uuid).limit(1))
                    current_analysis = current_analysis_res.scalars().first()
                    if current_analysis:
                        current_analysis.status = "completed"
                        current_analysis.file_hash = file_hash
                        current_analysis.pipeline_version = pipeline_version
                        current_analysis.filename = filename

                    if cached_result and current_result:
                        current_result.file_activity = cached_result.file_activity
                        current_result.docker_output = cached_result.docker_output
                        current_result.results = cached_result.results

                    await db.commit()
                    _copy_artifacts(str(cached.analysis_id), str(analysis_uuid))
                    return

                # Store file on disk
                class _MemUpload:
                    def __init__(self, filename: str, data: bytes):
                        import io

                        self.filename = filename
                        self.file = io.BytesIO(data)

                mem = _MemUpload(filename=filename, data=content)
                FileOperations.store_file_by_hash(file=mem, file_hash=file_hash, pipeline_version=pipeline_version)

                upload_folder = FileOperations.user_upload(str(analysis_id))
                if not upload_folder:
                    await _set_error("Не удалось создать директорию для загрузки")
                    return

                mem2 = _MemUpload(filename=filename, data=content)
                FileOperations.user_file_upload(file=mem2, user_upload_folder=upload_folder)

                # Update analysis metadata
                analysis_res = await db.execute(select(Analysis).where(Analysis.analysis_id == analysis_uuid).limit(1))
                analysis = analysis_res.scalars().first()
                if analysis:
                    analysis.filename = filename
                    analysis.file_hash = file_hash
                    analysis.pipeline_version = pipeline_version
                    analysis.status = "queued"
                    await db.commit()

                # Enqueue analysis pipeline
                analyze_file_task.delay(filename, str(analysis_id), str(user_id), file_hash, pipeline_version)
            finally:
                await db.close()

        return asyncio.run(_run())

    return download_url_and_enqueue_analysis_task
