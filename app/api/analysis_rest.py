import asyncio
import csv
import json
import math
import os
import re
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.auth import uuid_by_token
from app.celery_app import analyze_file_task
from app.core.db import AsyncSessionLocal, get_db
from app.core.settings import settings
from app.models.analysis import Analysis
from app.models.analysis_subscriber import AnalysisSubscriber
from app.repositories.analysis_artifacts_repository import AnalysisArtifactsRepository
from app.services.audit_service import AuditService
from app.services.hash_cache_service import HashCacheService
from app.services.user_service import UserService
from app.utils.file_operations import FileOperations
from app.utils.logging import Logger


router = APIRouter()


@router.get("/history")
async def history_endpoint(request: Request, db: AsyncSession = Depends(get_db)):
    userservice = UserService(db)
    user_id = uuid_by_token(request.cookies.get("refresh_token"))
    rows = await userservice.get_user_analyses(user_id)

    history = []
    for row in rows:
        ts = getattr(row, "timestamp", None) or row[0]
        history.append(
            {
                "timestamp": ts.isoformat() if ts else None,
                "filename": getattr(row, "filename", None) or row[1],
                "status": getattr(row, "status", None) or row[2],
                "analysis_id": str(getattr(row, "analysis_id", None) or row[3]),
            }
        )

    return JSONResponse({"history": history})


@router.get("/meta/{analysis_id}")
async def analysis_meta(request: Request, analysis_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    user_id = uuid_by_token(request.cookies.get("refresh_token"))

    row = (
        await db.execute(
            select(Analysis)
            .outerjoin(AnalysisSubscriber, AnalysisSubscriber.analysis_id == Analysis.analysis_id)
            .where(
                (Analysis.analysis_id == analysis_id)
                & ((Analysis.user_id == user_id) | (AnalysisSubscriber.user_id == user_id))
            )
            .limit(1)
        )
    ).scalars().first()

    if not row:
        raise HTTPException(status_code=404, detail="analysis not found")

    danger_count = 0
    is_threat = False

    threats = AnalysisArtifactsRepository.load_threat_report(str(analysis_id))
    if isinstance(threats, list):
        danger_count = len(threats)
        is_threat = danger_count > 0

    return JSONResponse(
        {
            "analysis_id": str(row.analysis_id),
            "status": row.status,
            "filename": row.filename,
            "timestamp": row.timestamp.isoformat() if getattr(row, "timestamp", None) else None,
            "sha256": row.file_hash,
            "pipeline_version": row.pipeline_version,
            "danger_count": danger_count,
            "is_threat": is_threat,
        }
    )


@router.post("/analyze")
async def analyze_file(request: Request, file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    try:
        userservice = UserService(db)
        refresh_token = request.cookies.get("refresh_token")
        uuid_user = uuid_by_token(refresh_token)

        content = await file.read()
        file_hash = await HashCacheService.calculate_hash(content)
        pipeline_version = settings.PIPELINE_VERSION

        cached = await userservice.find_latest_completed_by_hash(file_hash=file_hash, pipeline_version=pipeline_version)
        if cached:
            await userservice.subscribe_user_to_analysis(analysis_id=cached.analysis_id, user_id=uuid_user)
            await AuditService(db).log(
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
            return JSONResponse(
                {
                    "status": "completed",
                    "cached": True,
                    "analysis_id": str(cached.analysis_id),
                    "file_hash": file_hash,
                }
            )

        active = await userservice.find_active_by_hash(file_hash=file_hash, pipeline_version=pipeline_version)
        if active:
            await userservice.subscribe_user_to_analysis(analysis_id=active.analysis_id, user_id=uuid_user)
            await AuditService(db).log(
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
            return JSONResponse(
                {
                    "status": active.status,
                    "cached": False,
                    "joined": True,
                    "analysis_id": str(active.analysis_id),
                    "file_hash": file_hash,
                }
            )

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

        await AuditService(db).log(
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

        task = analyze_file_task.delay(file.filename, str(run_id), str(uuid_user), file_hash, pipeline_version)
        Logger.log(f"Файл загружен и анализ поставлен в очередь. ID анализа: {run_id}, task_id: {task.id}")
        return JSONResponse(
            {
                "status": "queued",
                "analysis_id": str(run_id),
                "task_id": task.id,
                "file_hash": file_hash,
            }
        )
    except Exception as e:
        Logger.log(f"Ошибка при анализе файла: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/results/{analysis_id}")
async def get_results(analysis_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    try:
        userservice = UserService(db)
        result_data = await userservice.get_result_data(str(analysis_id))
        await AuditService(db).log(request=None, event_type="analysis.results_viewed", metadata={"analysis_id": str(analysis_id)})
        return JSONResponse(result_data)
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": str(e)})


@router.get("/results/{analysis_id}/chunk")
async def get_results_chunk(analysis_id: uuid.UUID, offset: int = 0, limit: int = 50, db: AsyncSession = Depends(get_db)):
    try:
        userservice = UserService(db)
        result, total = await userservice.get_chunk_result(str(analysis_id), offset, limit)
        await AuditService(db).log(
            request=None,
            event_type="analysis.results_chunk_viewed",
            metadata={"analysis_id": str(analysis_id), "offset": offset, "limit": limit},
        )
        return JSONResponse({"chunk": result, "offset": offset, "limit": limit, "total": total})
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": str(e)})


@router.get("/clean-tree/{analysis_id}")
async def get_clean_tree(analysis_id: str, limit: int = 200, db: AsyncSession = Depends(get_db)):
    try:
        clean_csv_path = AnalysisArtifactsRepository.get_clean_tree_csv_path(analysis_id)

        if not os.path.exists(clean_csv_path):
            return JSONResponse(status_code=404, content={"error": "Файл clean_tree.csv не найден"})

        threats = AnalysisArtifactsRepository.load_threat_report(analysis_id)

        threats_map = {}
        danger_count_total = 0
        if isinstance(threats, list):
            danger_count_total = len(threats)
            for item in threats:
                line_number = item.get("line_number")
                if isinstance(line_number, int):
                    threats_map[line_number] = item

        rows = []
        columns = ["time", "event", "type", "pid", "tid", "details", "threat_level", "threat_msg"]

        total_rows = 0

        with open(clean_csv_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader, start=1):
                total_rows = idx
                if limit and len(rows) >= limit:
                    continue
                threat = threats_map.get(idx)

                base_user_data = row.get("User Data", "")
                extra_fields = row.get(None, [])
                parts = []

                if base_user_data not in (None, ""):
                    parts.append(str(base_user_data))

                if isinstance(extra_fields, list):
                    for val in extra_fields:
                        if val not in (None, ""):
                            parts.append(str(val))

                user_data_combined = " ".join(p.strip() for p in parts if str(p).strip())
                user_data_combined = user_data_combined.replace('"', "")

                details_value = ""

                if isinstance(user_data_combined, str) and user_data_combined:
                    path_match = re.search(r"(\\Device\\[^\s,\"]+.*)", user_data_combined)
                    if path_match:
                        details_value = path_match.group(1)
                    else:
                        drive_match = re.search(r"([A-Za-z]:\\[^\s,\"]+.*)", user_data_combined)
                        if drive_match:
                            details_value = drive_match.group(1)

                if not details_value:
                    details_value = user_data_combined

                rows.append(
                    {
                        "index": idx,
                        "time": row.get("Clock-Time", ""),
                        "event": row.get("Event Name", ""),
                        "type": row.get("Type", ""),
                        "pid": row.get("PID", ""),
                        "tid": row.get("TID", ""),
                        "details": details_value,
                        "threat_level": threat.get("level") if threat else None,
                        "threat_msg": threat.get("msg") if threat else None,
                    }
                )

        await AuditService(db).log(
            request=None,
            event_type="analysis.clean_tree_viewed",
            metadata={
                "analysis_id": analysis_id,
                "rows": len(rows),
                "total_rows": total_rows,
                "danger_count": danger_count_total,
                "limit": limit,
            },
        )

        return JSONResponse(
            {
                "columns": columns,
                "rows": rows,
                "total_rows": total_rows,
                "danger_count": danger_count_total,
                "limit": limit,
            }
        )
    except Exception as e:
        Logger.log(f"Ошибка при получении clean_tree: {str(e)}")
        return JSONResponse(status_code=500, content={"error": f"Ошибка при получении clean_tree: {str(e)}"})


@router.post("/convert-etl/{analysis_id}")
async def convert_etl(analysis_id: str, db: AsyncSession = Depends(get_db)):
    try:
        etl_file = AnalysisArtifactsRepository.get_trace_etl_path(analysis_id)
        json_file = os.path.join(AnalysisArtifactsRepository.get_base_dir(analysis_id), "trace.json")

        if not os.path.exists(etl_file):
            return JSONResponse(status_code=404, content={"error": "ETL файл не найден"})

        if os.path.exists(json_file):
            return JSONResponse(status_code=200, content={"status": "completed", "message": "ETL уже конвертирован в JSON"})

        async def run_conversion():
            try:
                csv_file = AnalysisArtifactsRepository.get_trace_csv_path(analysis_id)
                Logger.log(f"Конвертация ETL в CSV для анализа {analysis_id}...")

                with ThreadPoolExecutor() as pool:
                    await asyncio.get_event_loop().run_in_executor(
                        pool,
                        lambda: subprocess.run(
                            ["powershell", "-command", f"tracerpt {etl_file} -o {csv_file} -of CSV"],
                            check=True,
                        ),
                    )

                Logger.log(f"Конвертация ETL в JSON для анализа {analysis_id}...")

                with ThreadPoolExecutor() as pool:
                    await asyncio.get_event_loop().run_in_executor(
                        pool,
                        lambda: subprocess.run(
                            [
                                "powershell",
                                "-command",
                                f"Import-Csv {csv_file} | ConvertTo-Json | Out-File {json_file}",
                            ],
                            check=True,
                        ),
                    )

                Logger.log(f"Конвертация завершена для анализа {analysis_id}")
            except Exception as e:
                Logger.log(f"Ошибка при конвертации ETL: {str(e)}")

        await AuditService(db).log(request=None, event_type="analysis.conversion_started", metadata={"analysis_id": analysis_id})
        asyncio.create_task(run_conversion())

        return JSONResponse({"status": "processing", "message": "Конвертация ETL в JSON запущена. По завершении вы получите уведомление."})
    except Exception as e:
        Logger.log(f"Ошибка при запуске конвертации ETL: {str(e)}")
        return JSONResponse(status_code=500, content={"error": f"Ошибка при запуске конвертации ETL: {str(e)}"})


@router.get("/etl-json/{analysis_id}")
async def get_etl_json(analysis_id: str, db: AsyncSession = Depends(get_db)):
    try:
        json_file_path = os.path.join(AnalysisArtifactsRepository.get_base_dir(analysis_id), "trace.json")

        if not os.path.exists(json_file_path):
            etl_file = AnalysisArtifactsRepository.get_trace_etl_path(analysis_id)

            if not os.path.exists(etl_file):
                return JSONResponse(status_code=404, content={"error": "ETL файл не найден"})

            return JSONResponse(
                {
                    "status": "not_converted",
                    "message": "ETL файл требует конвертации. Используйте /analysis/convert-etl/{analysis_id}.",
                }
            )

        try:
            with open(json_file_path, "rb") as f:
                raw_data = f.read()

                if raw_data.startswith(b"\xef\xbb\xbf"):
                    encoding = "utf-8-sig"
                elif raw_data.startswith(b"\xff\xfe") or raw_data.startswith(b"\xfe\xff"):
                    encoding = "utf-16"
                else:
                    encoding = "utf-8"

                Logger.log(f"Определена кодировка файла: {encoding}")

            with open(json_file_path, "r", encoding=encoding, errors="replace") as json_file:
                try:
                    json_file.read(100)
                    await AuditService(db).log(request=None, event_type="analysis.json_available", metadata={"analysis_id": analysis_id})
                    return JSONResponse(
                        {
                            "status": "converted",
                            "message": "ETL файл успешно конвертирован в JSON. Используйте /analysis/etl-chunk/{analysis_id} для постраничной загрузки.",
                        }
                    )
                except Exception as e:
                    Logger.log(f"Ошибка при чтении JSON файла: {str(e)}")
                    return JSONResponse(status_code=500, content={"error": f"Ошибка при чтении JSON файла: {str(e)}"})
        except Exception as e:
            Logger.log(f"Ошибка при определении кодировки файла: {str(e)}")
            return JSONResponse(status_code=500, content={"error": f"Ошибка при определении кодировки файла: {str(e)}"})

    except Exception as e:
        Logger.log(f"Ошибка при получении ETL JSON: {str(e)}")
        return JSONResponse(status_code=500, content={"error": f"Ошибка при получении ETL JSON: {str(e)}"})


@router.get("/etl-chunk/{analysis_id}")
async def get_etl_chunk(analysis_id: str, offset: int = 0, limit: int = 200, db: AsyncSession = Depends(get_db)):
    try:
        json_file_path = os.path.join(AnalysisArtifactsRepository.get_base_dir(analysis_id), "trace.json")

        if not os.path.exists(json_file_path):
            return JSONResponse(status_code=404, content={"error": "ETL результаты не найдены"})

        try:
            with open(json_file_path, "rb") as f:
                raw_data = f.read()
                if raw_data.startswith(b"\xef\xbb\xbf"):
                    encoding = "utf-8-sig"
                elif raw_data.startswith(b"\xff\xfe") or raw_data.startswith(b"\xfe\xff"):
                    encoding = "utf-16"
                else:
                    encoding = "utf-8"

            with open(json_file_path, "r", encoding=encoding, errors="replace") as f:
                total_lines = sum(1 for _ in f)
                f.seek(0)

                for _ in range(offset):
                    if f.readline() == "":
                        break

                lines = []
                for _ in range(limit):
                    line = f.readline()
                    if line == "":
                        break
                    lines.append(line.rstrip("\n"))

            await AuditService(db).log(
                request=None,
                event_type="analysis.json_chunk_viewed",
                metadata={"analysis_id": analysis_id, "offset": offset, "limit": limit, "total": total_lines},
            )
            return JSONResponse({"chunk": lines, "offset": offset, "limit": limit, "total": total_lines})

        except Exception as e:
            Logger.log(f"Ошибка при чтении ETL результатов: {str(e)}")
            return JSONResponse(status_code=500, content={"error": f"Ошибка при чтении ETL результатов: {str(e)}"})

    except Exception as e:
        Logger.log(f"Ошибка при получении чанка ETL: {str(e)}")
        return JSONResponse(status_code=500, content={"error": f"Ошибка при получении чанка ETL: {str(e)}"})


@router.get("/download-json/{analysis_id}")
async def download_json(analysis_id: str, db: AsyncSession = Depends(get_db)):
    try:
        json_file_path = os.path.join(AnalysisArtifactsRepository.get_base_dir(analysis_id), "trace.json")

        if not os.path.exists(json_file_path):
            return JSONResponse(status_code=404, content={"error": "ETL результаты не найдены"})

        await AuditService(db).log(request=None, event_type="analysis.json_downloaded", metadata={"analysis_id": analysis_id})
        from fastapi.responses import FileResponse

        return FileResponse(path=str(json_file_path), filename=f"analysis_{analysis_id}.json", media_type="application/json")
    except Exception as e:
        Logger.log(f"Ошибка при скачивании JSON файла: {str(e)}")
        return JSONResponse(status_code=500, content={"error": f"Ошибка при скачивании JSON файла: {str(e)}"})


@router.get("/download-etl/{analysis_id}")
async def download_etl(analysis_id: str, format: str = "etl", db: AsyncSession = Depends(get_db)):
    try:
        etl_file = AnalysisArtifactsRepository.get_trace_etl_path(analysis_id)

        if format.lower() == "etl":
            await AuditService(db).log(request=None, event_type="analysis.etl_downloaded", metadata={"analysis_id": analysis_id, "format": format})
            from fastapi.responses import FileResponse

            return FileResponse(path=str(etl_file), filename=f"analysis_{analysis_id}.etl", media_type="application/octet-stream")
        raise HTTPException(status_code=400, detail="Неподдерживаемый формат")

    except Exception as e:
        Logger.log(f"Ошибка при скачивании ETL файла: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Ошибка при скачивании файла: {str(e)}")
