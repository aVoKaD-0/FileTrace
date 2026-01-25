import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.auth.auth import uuid_by_token
from app.infra.db.session import AsyncSessionLocal
from app.services.analysis_ws_service import AnalysisWsService
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
        except asyncio.CancelledError:
            return
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
                    ws_service = AnalysisWsService(db_ws)
                    result_data = await ws_service.get_analysis_snapshot(str(analysis_id))

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
    except asyncio.CancelledError:
        return
    except WebSocketDisconnect:
        Logger.log(f"disconnect websocket {analysis_id}, {websocket.client.host}")
    except Exception as e:
        Logger.log(f"websocket error {analysis_id}: {str(e)}")
    finally:
        manager.disconnect(analysis_id, websocket)
        try:
            await websocket.close()
        except Exception:
            pass


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
                    ws_service = AnalysisWsService(db_ws)
                    payload = await ws_service.get_history_payload(user_id=user_id)
                payload_str = json.dumps(payload, ensure_ascii=False)
                if payload_str != last_payload:
                    last_payload = payload_str
                    await websocket.send_text(payload_str)
            except Exception as loop_err:
                Logger.log(f"ws-history loop error: {str(loop_err)}")

            await asyncio.sleep(1)
    except asyncio.CancelledError:
        return
    except WebSocketDisconnect:
        return
    except Exception as e:
        Logger.log(f"ws-history error: {str(e)}")
        try:
            await websocket.close()
        except Exception:
            pass
