import os
import json
import uuid
import asyncio
import subprocess
from app.utils.logging import Logger
from app.auth.auth import uuid_by_token
from datetime import datetime, timezone
from fastapi.staticfiles import StaticFiles
from app.core.db import get_db
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from app.utils.websocket_manager import manager
from app.utils.sse_operations import subscribers
from sse_starlette.sse import EventSourceResponse
from app.services.user_service import UserService
from concurrent.futures import ThreadPoolExecutor
from app.utils.file_operations import FileOperations
from app.services.analysis_service import AnalysisService
from app.services.audit_service import AuditService
from app.repositories.analysis import docker
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, FileResponse
from fastapi import APIRouter, UploadFile, File, Request, HTTPException, Depends, WebSocket, WebSocketDisconnect

router = APIRouter(prefix="/analysis", tags=["analysis"])

router.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
async def root(request: Request, db: AsyncSession = Depends(get_db)):
    userservice = UserService(db)
    history = await userservice.get_user_analyses(uuid_by_token(request.cookies.get("refresh_token")))

    # Audit: analyses list viewed
    await AuditService(db).log(request=request, event_type="analysis.list_viewed", user_id=str(uuid_by_token(request.cookies.get("refresh_token"))))
    return templates.TemplateResponse(
        "analisys.html",
        {"request": request, "history": history}
    )

@router.get("/analysis/{analysis_id}")
async def get_analysis_page(request: Request, analysis_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    try:
        userservice = UserService(db)

        history = await userservice.get_user_analyses(uuid_by_token(request.cookies.get("refresh_token")))

        analysis_data = await userservice.get_result_data(str(analysis_id))
        if not analysis_data:
            return RedirectResponse(url="/")

        # Проверяем наличие JSON файла с ETL данными
        etl_output = ""
        json_file_path = f"{docker}\\analysis\\{analysis_id}\\trace.json"
        if os.path.exists(json_file_path):
            try:
                # Определяем кодировку файла
                with open(json_file_path, 'rb') as f:
                    raw_data = f.read()
                    
                    # Проверяем BOM (Byte Order Mark)
                    if raw_data.startswith(b'\xef\xbb\xbf'):  # UTF-8 BOM
                        encoding = 'utf-8-sig'
                    elif raw_data.startswith(b'\xff\xfe') or raw_data.startswith(b'\xfe\xff'):  # UTF-16 BOM
                        encoding = 'utf-16'
                    else:
                        encoding = 'utf-8'
                
                # Читаем только первые 500 строк файла
                with open(json_file_path, 'r', encoding=encoding, errors='replace') as f:
                    lines = []
                    for _ in range(500):  # Ограничиваем до 500 строк
                        line = f.readline()
                        if not line:
                            break
                        lines.append(line.rstrip('\n'))
                    etl_output = '\n'.join(lines)
            except Exception as e:
                Logger.log(f"Ошибка при чтении ETL результатов: {str(e)}")

        # Audit: analysis details viewed
        await AuditService(db).log(request=request, event_type="analysis.viewed", user_id=str(uuid_by_token(request.cookies.get("refresh_token"))), metadata={"analysis_id": str(analysis_id)})
        return templates.TemplateResponse(
            "analisys.html",
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
        return RedirectResponse(url="/")

@router.post("/analyze")
async def analyze_file(request: Request, file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    try:
        userservice = UserService(db)
        refresh_token = request.cookies.get("refresh_token")
        uuid = uuid_by_token(refresh_token)
        run_id = FileOperations.run_ID()
        upload_folder = FileOperations.user_upload(str(run_id))
        if not upload_folder:
            raise HTTPException(status_code=500, detail="Не удалось создать директорию для загрузки")
        FileOperations.user_file_upload(file=file, user_upload_folder=upload_folder)
        await userservice.create_analysis(user_id=uuid, filename=file.filename, status="running", analysis_id=run_id)
        await userservice.create_result(run_id)
        # Audit: analysis started
        await AuditService(db).log(request=request, event_type="analysis.started", user_id=str(uuid), metadata={"filename": file.filename, "analysis_id": str(run_id)})
        analysis_service = AnalysisService(file.filename, str(run_id), str(uuid))
        asyncio.create_task(analysis_service.analyze())
        Logger.log(f"Файл загружен и анализ запущен. ID анализа: {run_id}")
        return JSONResponse({
            "status": "running",
            "analysis_id": str(run_id)
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
        await websocket.receive_text() 
    except WebSocketDisconnect:
        Logger.log(f"disconnect websocket {analysis_id}, {websocket.client.host}")
        manager.disconnect(analysis_id, websocket)

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
        
        # Проверяем, существует ли JSON файл
        if not os.path.exists(json_file_path):
            etl_file = f"{docker}\\analysis\\{analysis_id}\\trace.etl"
            
            # Проверяем, существует ли ETL файл
            if not os.path.exists(etl_file):
                return JSONResponse(
                    status_code=404, 
                    content={"error": "ETL файл не найден"}
                )
            
            # Возвращаем статус, что конвертация не выполнена
            return JSONResponse({
                "status": "not_converted",
                "message": "ETL файл требует конвертации. Используйте /analysis/convert-etl/{analysis_id}."
            })
        
        try:
            # Читаем файл в бинарном режиме и определяем его кодировку
            with open(json_file_path, 'rb') as f:
                raw_data = f.read()
                
                # Проверяем BOM (Byte Order Mark)
                if raw_data.startswith(b'\xef\xbb\xbf'):  # UTF-8 BOM
                    encoding = 'utf-8-sig'
                elif raw_data.startswith(b'\xff\xfe') or raw_data.startswith(b'\xfe\xff'):  # UTF-16 BOM
                    encoding = 'utf-16'
                else:
                    # Если нет BOM, пробуем utf-8
                    encoding = 'utf-8'
                
                Logger.log(f"Определена кодировка файла: {encoding}")
                
            # Теперь читаем файл с правильной кодировкой
            with open(json_file_path, 'r', encoding=encoding, errors='replace') as json_file:
                try:
                    data = json_file.read(100)  # Читаем первые 100 символов для проверки
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
        
        # Проверяем, существует ли исходный ETL файл
        if not os.path.exists(etl_file):
            return JSONResponse(
                status_code=404, 
                content={"error": "ETL файл не найден"}
            )
        
        # Проверяем, существует ли уже JSON файл
        if os.path.exists(json_file):
            return JSONResponse(
                status_code=200, 
                content={"status": "completed", "message": "ETL уже конвертирован в JSON"}
            )
        
        # Запуск асинхронного процесса конвертации
        async def run_conversion():
            try:
                # Создаём CSV файл из ETL
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
                
                # Отправляем сообщение о завершении процесса через WebSocket
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
        
        # Запускаем конвертацию в фоновом режиме
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
