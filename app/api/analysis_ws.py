import asyncio
import json
import math

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.auth.auth import uuid_by_token
from app.core.db import AsyncSessionLocal
from app.core.settings import settings
from app.models.analysis import Analysis
from app.services.user_service import UserService
from app.utils.logging import Logger
from app.utils.sse_operations import subscribers
from app.utils.websocket_manager import manager
from sse_starlette.sse import EventSourceResponse


router = APIRouter()


@router.get("/sse")
async def sse_endpoint(request):
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
