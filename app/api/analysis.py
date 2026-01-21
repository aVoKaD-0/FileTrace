import os
import json
import uuid
import asyncio
import subprocess
import csv
import re
from app.utils.logging import Logger
from app.auth.auth import uuid_by_token
from datetime import datetime, timezone
import math
from fastapi.staticfiles import StaticFiles
from app.core.db import get_db, AsyncSessionLocal
from app.core.settings import settings
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.utils.websocket_manager import manager
from app.utils.sse_operations import subscribers
from sse_starlette.sse import EventSourceResponse
from app.services.user_service import UserService
from app.services.hash_cache_service import HashCacheService
from concurrent.futures import ThreadPoolExecutor
from app.utils.file_operations import FileOperations
from app.services.analysis_service import AnalysisService
from app.services.audit_service import AuditService
from app.repositories.analysis import docker
from app.celery_app import analyze_file_task
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, FileResponse, Response
from fastapi import APIRouter, UploadFile, File, Request, HTTPException, Depends, WebSocket, WebSocketDisconnect
from app.models.analysis import Analysis
from app.models.analysis_subscriber import AnalysisSubscriber

router = APIRouter(prefix="/analysis", tags=["analysis"])

router.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
async def root(request: Request, db: AsyncSession = Depends(get_db)):
    userservice = UserService(db)
    history = await userservice.get_user_analyses(uuid_by_token(request.cookies.get("refresh_token")))

    await AuditService(db).log(request=request, event_type="analysis.list_viewed", user_id=str(uuid_by_token(request.cookies.get("refresh_token"))))
    return templates.TemplateResponse(
        "analysis.html",
        {"request": request, "history": history}
    )


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

    base_dir = f"{docker}\\analysis\\{analysis_id}"
    threat_report_path = os.path.join(base_dir, "threat_report.json")

    danger_count = 0
    is_threat = False
    if os.path.exists(threat_report_path):
        try:
            with open(threat_report_path, "r", encoding="utf-8") as f:
                threats = json.load(f)
                if isinstance(threats, list):
                    danger_count = len(threats)
                    is_threat = danger_count > 0
        except Exception as e:
            Logger.log(f"Ошибка при чтении threat_report.json meta: {str(e)}")

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

@router.get("/analysis/{analysis_id}")
async def get_analysis_page(request: Request, analysis_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    try:
        userservice = UserService(db)

        history = await userservice.get_user_analyses(uuid_by_token(request.cookies.get("refresh_token")))

        analysis_data = await userservice.get_result_data(str(analysis_id))
        if not analysis_data:
            return RedirectResponse(url="/main")

        etl_output = ""
        json_file_path = f"{docker}\\analysis\\{analysis_id}\\trace.json"
        if os.path.exists(json_file_path):
            try:
                with open(json_file_path, 'rb') as f:
                    raw_data = f.read()
                    
                    if raw_data.startswith(b'\xef\xbb\xbf'): 
                        encoding = 'utf-8-sig'
                    elif raw_data.startswith(b'\xff\xfe') or raw_data.startswith(b'\xfe\xff'): 
                        encoding = 'utf-16'
                    else:
                        encoding = 'utf-8'
                
                with open(json_file_path, 'r', encoding=encoding, errors='replace') as f:
                    lines = []
                    for _ in range(500):  
                        line = f.readline()
                        if not line:
                            break
                        lines.append(line.rstrip('\n'))
                    etl_output = '\n'.join(lines)
            except Exception as e:
                Logger.log(f"Ошибка при чтении ETL результатов: {str(e)}")

        await AuditService(db).log(request=request, event_type="analysis.viewed", user_id=str(uuid_by_token(request.cookies.get("refresh_token"))), metadata={"analysis_id": str(analysis_id)})
        return templates.TemplateResponse(
            "analysis.html",
            {
                "request": request,
                "analysis_id": str(analysis_id),
                "status": analysis_data.get("status", "unknown"),
                "file_activity": analysis_data.get("file_activity", ""),
                "docker_output": analysis_data.get("docker_output", ""),
                "etl_output": etl_output,
                "history": history
            }
        )
    except Exception as e:
        Logger.log(f"Ошибка при получении страницы анализа: {str(e)}")
        return RedirectResponse(url="/main")

@router.post("/analyze")
async def analyze_file(request: Request, file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    try:
        userservice = UserService(db)
        refresh_token = request.cookies.get("refresh_token")
        uuid = uuid_by_token(refresh_token)

        content = await file.read()
        file_hash = await HashCacheService.calculate_hash(content)
        pipeline_version = settings.PIPELINE_VERSION

        cached = await userservice.find_latest_completed_by_hash(file_hash=file_hash, pipeline_version=pipeline_version)
        if cached:
            await userservice.subscribe_user_to_analysis(analysis_id=cached.analysis_id, user_id=uuid)
            await AuditService(db).log(
                request=request,
                event_type="analysis.cache_hit",
                user_id=str(uuid),
                metadata={"filename": file.filename, "analysis_id": str(cached.analysis_id), "file_hash": file_hash, "pipeline_version": pipeline_version},
            )
            return JSONResponse({
                "status": "completed",
                "cached": True,
                "analysis_id": str(cached.analysis_id),
                "file_hash": file_hash,
            })

        active = await userservice.find_active_by_hash(file_hash=file_hash, pipeline_version=pipeline_version)
        if active:
            await userservice.subscribe_user_to_analysis(analysis_id=active.analysis_id, user_id=uuid)
            await AuditService(db).log(
                request=request,
                event_type="analysis.joined_existing",
                user_id=str(uuid),
                metadata={"filename": file.filename, "analysis_id": str(active.analysis_id), "file_hash": file_hash, "pipeline_version": pipeline_version},
            )
            return JSONResponse({
                "status": active.status,
                "cached": False,
                "joined": True,
                "analysis_id": str(active.analysis_id),
                "file_hash": file_hash,
            })

        run_id = FileOperations.run_ID()

        await file.seek(0)
        FileOperations.store_file_by_hash(file=file, file_hash=file_hash, pipeline_version=pipeline_version)
        await file.seek(0)

        upload_folder = FileOperations.user_upload(str(run_id))
        if not upload_folder:
            raise HTTPException(status_code=500, detail="Не удалось создать директорию для загрузки")
        FileOperations.user_file_upload(file=file, user_upload_folder=upload_folder)

        await userservice.create_hash_analysis(
            user_id=uuid,
            filename=file.filename,
            status="queued",
            analysis_id=run_id,
            file_hash=file_hash,
            pipeline_version=pipeline_version,
        )
        await userservice.subscribe_user_to_analysis(analysis_id=run_id, user_id=uuid)
        await userservice.create_result(run_id)

        await AuditService(db).log(
            request=request,
            event_type="analysis.queued",
            user_id=str(uuid),
            metadata={"filename": file.filename, "analysis_id": str(run_id), "file_hash": file_hash, "pipeline_version": pipeline_version},
        )

        task = analyze_file_task.delay(file.filename, str(run_id), str(uuid), file_hash, pipeline_version)
        Logger.log(f"Файл загружен и анализ поставлен в очередь. ID анализа: {run_id}, task_id: {task.id}")
        return JSONResponse({
            "status": "queued",
            "analysis_id": str(run_id),
            "task_id": task.id,
            "file_hash": file_hash,
        })
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
        await AuditService(db).log(request=None, event_type="analysis.results_chunk_viewed", metadata={"analysis_id": str(analysis_id), "offset": offset, "limit": limit})
        return JSONResponse({
            "chunk": result,
            "offset": offset,
            "limit": limit,
            "total": total
        })
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": str(e)})


@router.get("/download/{analysis_id}", response_class=HTMLResponse)
async def download_page(analysis_id: str):
    download_url = f"/results/{analysis_id}/download"
    return f"""
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <title>Начало загрузки</title>
        <script>
            window.onload = function() {{
                window.location.href = "{download_url}";
            }};
        </script>
    </head>
    <body>
        <p>Если загрузка не началась автоматически, нажмите <a href="{download_url}">здесь</a>.</p>
    </body>
    </html>
    """

@router.get("/sse")
async def sse_endpoint(request: Request):
    Logger.log("SSE endpoint called")
    async def event_generator():
        Logger.log("Event generator started")
        q = asyncio.Queue()
        subscribers.append(q)
        try:
            while True:
                if await request.is_disconnected():
                    Logger.log("Client disconnected")
                    break
                data = await q.get()
                Logger.log(f"Sending data: {data}")
                yield f"data: {json.dumps(data)}\n\n"
        finally:
            Logger.log("Event generator finished")
            subscribers.remove(q)
    return EventSourceResponse(event_generator())
    
@router.websocket("/ws/{analysis_id}")
async def websocket_endpoint(websocket: WebSocket, analysis_id: str):
    await manager.connect(analysis_id, websocket)
    try:
        Logger.log(f"connect websocket {analysis_id}, {websocket.client.host}")
        last_status = None
        last_docker_len = 0
        while True:
            try:
                async with AsyncSessionLocal() as db_ws:
                    userservice = UserService(db_ws)
                    result_data = await userservice.get_result_data(str(analysis_id))

                status = (result_data or {}).get("status")
                if status and status != last_status:
                    last_status = status
                    Logger.log(f"ws push status {analysis_id}: {status}")
                    await websocket.send_text(json.dumps({"status": status}))

                docker_output = (result_data or {}).get("docker_output") or ""
                if docker_output and len(docker_output) > last_docker_len:
                    delta = docker_output[last_docker_len:]
                    last_docker_len = len(docker_output)
                    await websocket.send_text(json.dumps({"event": "docker_log", "message": delta}))
            except Exception as loop_err:
                Logger.log(f"ws loop error {analysis_id}: {str(loop_err)}")

            await asyncio.sleep(1)
    except WebSocketDisconnect:
        Logger.log(f"disconnect websocket {analysis_id}, {websocket.client.host}")
        manager.disconnect(analysis_id, websocket)
    except Exception as e:
        Logger.log(f"websocket error {analysis_id}: {str(e)}")
        manager.disconnect(analysis_id, websocket)


@router.websocket("/ws-history")
async def websocket_history_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        refresh_token = websocket.cookies.get("refresh_token")
        if not refresh_token:
            await websocket.close(code=1008)
            return
        user_id = uuid_by_token(refresh_token)

        last_payload = None
        while True:
            try:
                async with AsyncSessionLocal() as db_ws:
                    # Full history for UI
                    userservice = UserService(db_ws)
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

                    # Queue position/ETA based on global active queue (running/queued)
                    # so the user can see realistic waiting time even if other users have queued analyses.
                    global_active_rows = (
                        await db_ws.execute(
                            select(Analysis.analysis_id, Analysis.status, Analysis.timestamp)
                            .where(Analysis.status.in_(["queued", "running"]))
                            .order_by(Analysis.timestamp.asc())
                        )
                    ).all()

                    active_total = len(global_active_rows)
                    max_conc = max(int(getattr(settings, "MAX_CONCURRENT_ANALYSES", 1) or 1), 1)

                    positions = {}
                    for idx, (aid, st, ts) in enumerate(global_active_rows):
                        ahead = idx
                        eta_minutes = int(3 * math.ceil(ahead / max_conc)) if ahead > 0 else 0
                        positions[str(aid)] = {
                            "active_position": idx + 1,
                            "active_total": active_total,
                            "ahead": ahead,
                            "eta_minutes": eta_minutes,
                        }

                    # Only attach queue info to analyses visible in user's history
                    for item in history:
                        if item.get("status") in ("queued", "running"):
                            q = positions.get(item["analysis_id"])
                            if q:
                                item.update(q)

                payload = {"event": "history", "history": history}
                payload_str = json.dumps(payload, ensure_ascii=False)
                if payload_str != last_payload:
                    last_payload = payload_str
                    await websocket.send_text(payload_str)
            except Exception as loop_err:
                Logger.log(f"ws-history loop error: {str(loop_err)}")

            await asyncio.sleep(1)
    except WebSocketDisconnect:
        return
    except Exception as e:
        Logger.log(f"ws-history error: {str(e)}")
        try:
            await websocket.close()
        except Exception:
            pass

@router.get("/download-etl/{analysis_id}")
async def download_etl(analysis_id: str, format: str = "etl", db: AsyncSession = Depends(get_db)):
    try:
        etl_file = f"{docker}\\analysis\\{analysis_id}\\trace.etl"

        if format.lower() == "etl":
            await AuditService(db).log(request=None, event_type="analysis.etl_downloaded", metadata={"analysis_id": analysis_id, "format": format})
            return FileResponse(
                path=str(etl_file),
                filename=f"analysis_{analysis_id}.etl",
                media_type="application/octet-stream"
            )
        else:
            raise HTTPException(status_code=400, detail="Неподдерживаемый формат")
    
    except Exception as e:
        Logger.log(f"Ошибка при скачивании ETL файла: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Ошибка при скачивании файла: {str(e)}")

@router.get("/etl-json/{analysis_id}")
async def get_etl_json(analysis_id: str, db: AsyncSession = Depends(get_db)):
    try:
        json_file_path = f"{docker}\\analysis\\{analysis_id}\\trace.json"
        
        if not os.path.exists(json_file_path):
            etl_file = f"{docker}\\analysis\\{analysis_id}\\trace.etl"
            
            if not os.path.exists(etl_file):
                return JSONResponse(
                    status_code=404, 
                    content={"error": "ETL файл не найден"}
                )
            
            return JSONResponse({
                "status": "not_converted",
                "message": "ETL файл требует конвертации. Используйте /analysis/convert-etl/{analysis_id}."
            })
        
        try:
            with open(json_file_path, 'rb') as f:
                raw_data = f.read()
                
                if raw_data.startswith(b'\xef\xbb\xbf'):  
                    encoding = 'utf-8-sig'
                elif raw_data.startswith(b'\xff\xfe') or raw_data.startswith(b'\xfe\xff'): 
                    encoding = 'utf-16'
                else:
                    encoding = 'utf-8'
                
                Logger.log(f"Определена кодировка файла: {encoding}")
                
            with open(json_file_path, 'r', encoding=encoding, errors='replace') as json_file:
                try:
                    data = json_file.read(100) 
                    await AuditService(db).log(request=None, event_type="analysis.json_available", metadata={"analysis_id": analysis_id})
                    return JSONResponse({
                        "status": "converted",
                        "message": "ETL файл успешно конвертирован в JSON. Используйте /analysis/etl-chunk/{analysis_id} для постраничной загрузки."
                    })
                except Exception as e:
                    Logger.log(f"Ошибка при чтении JSON файла: {str(e)}")
                    return JSONResponse(
                        status_code=500, 
                        content={"error": f"Ошибка при чтении JSON файла: {str(e)}"}
                    )
        except Exception as e:
            Logger.log(f"Ошибка при определении кодировки файла: {str(e)}")
            return JSONResponse(
                status_code=500, 
                content={"error": f"Ошибка при определении кодировки файла: {str(e)}"}
            )
    
    except Exception as e:
        Logger.log(f"Ошибка при получении ETL JSON: {str(e)}")
        return JSONResponse(
            status_code=500, 
            content={"error": f"Ошибка при получении ETL JSON: {str(e)}"}
        )

@router.get("/etl-chunk/{analysis_id}")
async def get_etl_chunk(analysis_id: str, offset: int = 0, limit: int = 200, db: AsyncSession = Depends(get_db)):
    try:
        json_file_path = f"{docker}\\analysis\\{analysis_id}\\trace.json"
        
        if not os.path.exists(json_file_path):
            return JSONResponse(
                status_code=404, 
                content={"error": "ETL результаты не найдены"}
            )
            
        try:
            with open(json_file_path, 'rb') as f:
                raw_data = f.read()
                if raw_data.startswith(b'\xef\xbb\xbf'): 
                    encoding = 'utf-8-sig'
                elif raw_data.startswith(b'\xff\xfe') or raw_data.startswith(b'\xfe\xff'):
                    encoding = 'utf-16'
                else:
                    encoding = 'utf-8'
            
            with open(json_file_path, 'r', encoding=encoding, errors='replace') as f:
                total_lines = sum(1 for _ in f)
                f.seek(0)
                
                for _ in range(offset):
                    if f.readline() == '':
                        break
                
                lines = []
                for _ in range(limit):
                    line = f.readline()
                    if line == '':
                        break
                    lines.append(line.rstrip('\n'))
            
            await AuditService(db).log(request=None, event_type="analysis.json_chunk_viewed", metadata={"analysis_id": analysis_id, "offset": offset, "limit": limit, "total": total_lines})
            return JSONResponse({
                "chunk": lines,
                "offset": offset,
                "limit": limit,
                "total": total_lines
            })
            
        except Exception as e:
            Logger.log(f"Ошибка при чтении ETL результатов: {str(e)}")
            return JSONResponse(
                status_code=500, 
                content={"error": f"Ошибка при чтении ETL результатов: {str(e)}"}
            )
    
    except Exception as e:
        Logger.log(f"Ошибка при получении чанка ETL: {str(e)}")
        return JSONResponse(
            status_code=500, 
            content={"error": f"Ошибка при получении чанка ETL: {str(e)}"}
        )

@router.get("/download-json/{analysis_id}")
async def download_json(analysis_id: str, db: AsyncSession = Depends(get_db)):
    try:
        json_file_path = f"{docker}\\analysis\\{analysis_id}\\trace.json"
        
        if not os.path.exists(json_file_path):
            return JSONResponse(
                status_code=404, 
                content={"error": "ETL результаты не найдены"}
            )
            
        await AuditService(db).log(request=None, event_type="analysis.json_downloaded", metadata={"analysis_id": analysis_id})
        return FileResponse(
            path=str(json_file_path),
            filename=f"analysis_{analysis_id}.json",
            media_type="application/json"
        )
    except Exception as e:
        Logger.log(f"Ошибка при скачивании JSON файла: {str(e)}")
        return JSONResponse(
            status_code=500, 
            content={"error": f"Ошибка при скачивании JSON файла: {str(e)}"}
        )

@router.post("/convert-etl/{analysis_id}")
async def convert_etl(analysis_id: str, db: AsyncSession = Depends(get_db)):
    try:
        etl_file = f"{docker}\\analysis\\{analysis_id}\\trace.etl"
        json_file = f"{docker}\\analysis\\{analysis_id}\\trace.json"
        
        if not os.path.exists(etl_file):
            return JSONResponse(
                status_code=404, 
                content={"error": "ETL файл не найден"}
            )
        
        if os.path.exists(json_file):
            return JSONResponse(
                status_code=200, 
                content={"status": "completed", "message": "ETL уже конвертирован в JSON"}
            )
        
        async def run_conversion():
            try:
                csv_file = f"{docker}\\analysis\\{analysis_id}\\trace.csv"
                Logger.log(f"Конвертация ETL в CSV для анализа {analysis_id}...")
                
                with ThreadPoolExecutor() as pool:
                    await asyncio.get_event_loop().run_in_executor(
                        pool,
                        lambda: subprocess.run(["powershell", "-command", f"tracerpt {etl_file} -o {csv_file} -of CSV"], check=True)
                    )
                
                Logger.log(f"Конвертация ETL в JSON для анализа {analysis_id}...")
                
                with ThreadPoolExecutor() as pool:
                    await asyncio.get_event_loop().run_in_executor(
                        pool,
                        lambda: subprocess.run(["powershell", "-command", f"Import-Csv {csv_file} | ConvertTo-Json | Out-File {json_file}"], check=True)
                    )
                
                Logger.log(f"Конвертация завершена для анализа {analysis_id}")
                
                await manager.send_message(analysis_id, json.dumps({
                    "event": "etl_converted",
                    "message": "ETL данные успешно конвертированы"
                }))
            except Exception as e:
                Logger.log(f"Ошибка при конвертации ETL: {str(e)}")
                await manager.send_message(analysis_id, json.dumps({
                    "event": "etl_conversion_error",
                    "message": f"Ошибка при конвертации ETL: {str(e)}"
                }))
        
        await AuditService(db).log(request=None, event_type="analysis.conversion_started", metadata={"analysis_id": analysis_id})
        asyncio.create_task(run_conversion())
        
        return JSONResponse({
            "status": "processing",
            "message": "Конвертация ETL в JSON запущена. По завершении вы получите уведомление."
        })
    except Exception as e:
        Logger.log(f"Ошибка при запуске конвертации ETL: {str(e)}")
        return JSONResponse(
            status_code=500, 
            content={"error": f"Ошибка при запуске конвертации ETL: {str(e)}"}
        )

@router.get("/clean-tree/{analysis_id}")
async def get_clean_tree(analysis_id: str, limit: int = 200, db: AsyncSession = Depends(get_db)):
    try:
        base_dir = f"{docker}\\analysis\\{analysis_id}"
        clean_csv_path = os.path.join(base_dir, "clean_tree.csv")
        threat_report_path = os.path.join(base_dir, "threat_report.json")

        if not os.path.exists(clean_csv_path):
            return JSONResponse(
                status_code=404,
                content={"error": "Файл clean_tree.csv не найден"}
            )

        threats_map = {}
        danger_count_total = 0
        if os.path.exists(threat_report_path):
            try:
                with open(threat_report_path, "r", encoding="utf-8") as f:
                    threats = json.load(f)
                    if isinstance(threats, list):
                        danger_count_total = len(threats)
                    for item in threats:
                        line_number = item.get("line_number")
                        if isinstance(line_number, int):
                            threats_map[line_number] = item
            except Exception as e:
                Logger.log(f"Ошибка при чтении threat_report.json: {str(e)}")

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
                    path_match = re.search(r'(\\Device\\[^\s,\"]+.*)', user_data_combined)
                    if path_match:
                        details_value = path_match.group(1)
                    else:
                        drive_match = re.search(r'([A-Za-z]:\\[^\s,\"]+.*)', user_data_combined)
                        if drive_match:
                            details_value = drive_match.group(1)

                if not details_value:
                    details_value = user_data_combined

                rows.append({
                    "index": idx,
                    "time": row.get("Clock-Time", ""),
                    "event": row.get("Event Name", ""),
                    "type": row.get("Type", ""),
                    "pid": row.get("PID", ""),
                    "tid": row.get("TID", ""),
                    "details": details_value,
                    "threat_level": threat.get("level") if threat else None,
                    "threat_msg": threat.get("msg") if threat else None,
                })

        await AuditService(db).log(
            request=None,
            event_type="analysis.clean_tree_viewed",
            metadata={"analysis_id": analysis_id, "rows": len(rows), "total_rows": total_rows, "danger_count": danger_count_total, "limit": limit}
        )

        return JSONResponse({
            "columns": columns,
            "rows": rows,
            "total_rows": total_rows,
            "danger_count": danger_count_total,
            "limit": limit,
        })
    except Exception as e:
        Logger.log(f"Ошибка при получении clean_tree: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Ошибка при получении clean_tree: {str(e)}"}
        )

@router.get("/download-trace-csv/{analysis_id}")
async def download_trace_csv(analysis_id: str, db: AsyncSession = Depends(get_db)):
    try:
        csv_file_path = f"{docker}\\analysis\\{analysis_id}\\trace.csv"

        if not os.path.exists(csv_file_path):
            return JSONResponse(
                status_code=404,
                content={"error": "trace.csv не найден"}
            )

        userservice = UserService(db)
        result_data = await userservice.get_result_data(str(analysis_id))
        target_exe = (result_data or {}).get("filename")
        target_exe_lower = (target_exe or "").lower()
        target_exe_lower_no_ext = target_exe_lower[:-4] if target_exe_lower.endswith(".exe") else target_exe_lower

        filtered_lines = []
        with open(csv_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            header = f.readline()
            if header:
                filtered_lines.append(header)

            found = False
            for line in f:
                if not found and target_exe_lower:
                    l = line.lower()
                    if (
                        ("," + target_exe_lower + ",") in l or
                        ("\\" + target_exe_lower) in l or
                        ("\\" + target_exe_lower_no_ext + ".exe") in l or
                        (" " + target_exe_lower) in l or
                        (" " + target_exe_lower_no_ext) in l
                    ):
                        found = True

                if found or not target_exe_lower:
                    filtered_lines.append(line)

        if target_exe_lower and len(filtered_lines) <= 1:
            filtered_lines = None

        await AuditService(db).log(request=None, event_type="analysis.trace_csv_downloaded", metadata={"analysis_id": analysis_id})
        if filtered_lines is None:
            return FileResponse(
                path=str(csv_file_path),
                filename=f"analysis_{analysis_id}_trace.csv",
                media_type="text/csv"
            )

        return Response(
            content="".join(filtered_lines),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=analysis_{analysis_id}_trace.csv"},
        )
    except Exception as e:
        Logger.log(f"Ошибка при скачивании trace.csv: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Ошибка при скачивании trace.csv: {str(e)}"}
        )

@router.get("/download-clean-tree-csv/{analysis_id}")
async def download_clean_tree_csv(analysis_id: str, db: AsyncSession = Depends(get_db)):
    try:
        base_dir = f"{docker}\\analysis\\{analysis_id}"
        csv_file_path = os.path.join(base_dir, "clean_tree.csv")

        if not os.path.exists(csv_file_path):
            return JSONResponse(
                status_code=404,
                content={"error": "clean_tree.csv не найден"}
            )

        await AuditService(db).log(request=None, event_type="analysis.clean_tree_csv_downloaded", metadata={"analysis_id": analysis_id})
        return FileResponse(
            path=str(csv_file_path),
            filename=f"analysis_{analysis_id}_clean_tree.csv",
            media_type="text/csv"
        )
    except Exception as e:
        Logger.log(f"Ошибка при скачивании clean_tree.csv: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Ошибка при скачивании clean_tree.csv: {str(e)}"}
        )

@router.get("/download-clean-tree-json/{analysis_id}")
async def download_clean_tree_json(analysis_id: str, db: AsyncSession = Depends(get_db)):
    try:
        base_dir = f"{docker}\\analysis\\{analysis_id}"
        json_file_path = os.path.join(base_dir, "clean_tree.json")

        if not os.path.exists(json_file_path):
            return JSONResponse(
                status_code=404,
                content={"error": "clean_tree.json не найден"}
            )

        await AuditService(db).log(request=None, event_type="analysis.clean_tree_json_downloaded", metadata={"analysis_id": analysis_id})
        return FileResponse(
            path=str(json_file_path),
            filename=f"analysis_{analysis_id}_clean_tree.json",
            media_type="application/json"
        )
    except Exception as e:
        Logger.log(f"Ошибка при скачивании clean_tree.json: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Ошибка при скачивании clean_tree.json: {str(e)}"}
        )

@router.get("/download-threat-report/{analysis_id}")
async def download_threat_report(analysis_id: str, db: AsyncSession = Depends(get_db)):
    try:
        base_dir = f"{docker}\\analysis\\{analysis_id}"
        json_file_path = os.path.join(base_dir, "threat_report.json")

        if not os.path.exists(json_file_path):
            return JSONResponse(
                status_code=404,
                content={"error": "threat_report.json не найден"}
            )

        await AuditService(db).log(request=None, event_type="analysis.threat_report_downloaded", metadata={"analysis_id": analysis_id})
        return FileResponse(
            path=str(json_file_path),
            filename=f"analysis_{analysis_id}_threat_report.json",
            media_type="application/json"
        )
    except Exception as e:
        Logger.log(f"Ошибка при скачивании threat_report.json: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Ошибка при скачивании threat_report.json: {str(e)}"}
        )
