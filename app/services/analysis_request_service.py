import uuid

from fastapi import HTTPException, Request, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.auth import uuid_by_token
from app.core.settings import settings
from app.services.audit_service import AuditService
from app.services.hash_cache_service import HashCacheService
from app.services.user_service import UserService
from app.utils.file_operations import FileOperations
from app.utils.logging import Logger


class AnalysisRequestService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def analyze_upload(self, *, request: Request, file: UploadFile) -> dict:
        userservice = UserService(self.db)
        refresh_token = request.cookies.get("refresh_token")
        uuid_user = uuid_by_token(refresh_token)

        if not uuid_user:
            raise HTTPException(status_code=401, detail="unauthorized")

        content = await file.read()

        max_upload = int(getattr(settings, "MAX_UPLOAD_BYTES", 50 * 1024 * 1024) or 50 * 1024 * 1024)
        if max_upload > 0 and len(content) > max_upload:
            raise HTTPException(status_code=413, detail="Файл слишком большой")

        filename = getattr(file, "filename", None) or ""
        if not filename:
            raise HTTPException(status_code=400, detail="Не удалось определить имя файла")

        if not filename.lower().endswith(".exe"):
            raise HTTPException(status_code=400, detail="Разрешены только .exe файлы")

        if len(content) < 2 or content[:2] != b"MZ":
            raise HTTPException(status_code=400, detail="Файл не похож на Windows PE (.exe)")

        file_hash = await HashCacheService.calculate_hash(content)
        pipeline_version = settings.PIPELINE_VERSION

        cached = await userservice.find_latest_completed_by_hash(file_hash=file_hash, pipeline_version=pipeline_version)
        if cached:
            await userservice.subscribe_user_to_analysis(analysis_id=cached.analysis_id, user_id=uuid_user)
            await AuditService(self.db).log(
                request=request,
                event_type="analysis.cache_hit",
                user_id=str(uuid_user),
                metadata={
                    "filename": file.filename,
                    "analysis_id": str(cached.analysis_id),
                    "file_hash": file_hash,
                    "pipeline_version": pipeline_version,
                },
            )
            return {
                "status": "completed",
                "cached": True,
                "analysis_id": str(cached.analysis_id),
                "file_hash": file_hash,
            }

        active = await userservice.find_active_by_hash(file_hash=file_hash, pipeline_version=pipeline_version)
        if active:
            await userservice.subscribe_user_to_analysis(analysis_id=active.analysis_id, user_id=uuid_user)
            await AuditService(self.db).log(
                request=request,
                event_type="analysis.joined_existing",
                user_id=str(uuid_user),
                metadata={
                    "filename": file.filename,
                    "analysis_id": str(active.analysis_id),
                    "file_hash": file_hash,
                    "pipeline_version": pipeline_version,
                },
            )
            return {
                "status": active.status,
                "cached": False,
                "joined": True,
                "analysis_id": str(active.analysis_id),
                "file_hash": file_hash,
            }

        run_id = FileOperations.run_ID()

        await file.seek(0)
        FileOperations.store_file_by_hash(file=file, file_hash=file_hash, pipeline_version=pipeline_version)
        await file.seek(0)

        upload_folder = FileOperations.user_upload(str(run_id))
        if not upload_folder:
            raise HTTPException(status_code=500, detail="Не удалось создать директорию для загрузки")
        FileOperations.user_file_upload(file=file, user_upload_folder=upload_folder)

        await userservice.create_hash_analysis(
            user_id=uuid_user,
            filename=file.filename,
            status="queued",
            analysis_id=run_id,
            file_hash=file_hash,
            pipeline_version=pipeline_version,
        )
        await userservice.subscribe_user_to_analysis(analysis_id=run_id, user_id=uuid_user)
        await userservice.create_result(run_id)

        await AuditService(self.db).log(
            request=request,
            event_type="analysis.queued",
            user_id=str(uuid_user),
            metadata={
                "filename": file.filename,
                "analysis_id": str(run_id),
                "file_hash": file_hash,
                "pipeline_version": pipeline_version,
            },
        )

        from app.celery_app import analyze_file_task

        task = analyze_file_task.delay(file.filename, str(run_id), str(uuid_user), file_hash, pipeline_version)
        Logger.log(f"Файл загружен и анализ поставлен в очередь. ID анализа: {run_id}, task_id: {task.id}")

        return {
            "status": "queued",
            "analysis_id": str(run_id),
            "task_id": task.id,
            "file_hash": file_hash,
        }
