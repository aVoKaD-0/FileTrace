import os
import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.auth import uuid_by_token
from app.infra.db.deps import get_db
from app.infra.docker.paths import get_analysis_dir
from app.services.audit_service import AuditService
from app.services.user_service import UserService
from app.utils.logging import Logger


router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
async def root(request: Request, db: AsyncSession = Depends(get_db)):
    userservice = UserService(db)
    history = await userservice.get_user_analyses(uuid_by_token(request.cookies.get("refresh_token")))

    await AuditService(db).log(
        request=request,
        event_type="analysis.list_viewed",
        user_id=str(uuid_by_token(request.cookies.get("refresh_token"))),
    )
    return templates.TemplateResponse(
        "analysis.html",
        {"request": request, "history": history},
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
        json_file_path = os.path.join(get_analysis_dir(str(analysis_id)), "trace.json")
        if os.path.exists(json_file_path):
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
                    lines = []
                    for _ in range(500):
                        line = f.readline()
                        if not line:
                            break
                        lines.append(line.rstrip("\n"))
                    etl_output = "\n".join(lines)
            except Exception as e:
                Logger.log(f"Ошибка при чтении ETL результатов: {str(e)}")

        await AuditService(db).log(
            request=request,
            event_type="analysis.viewed",
            user_id=str(uuid_by_token(request.cookies.get("refresh_token"))),
            metadata={"analysis_id": str(analysis_id)},
        )
        return templates.TemplateResponse(
            "analysis.html",
            {
                "request": request,
                "analysis_id": str(analysis_id),
                "status": analysis_data.get("status", "unknown"),
                "file_activity": analysis_data.get("file_activity", ""),
                "docker_output": analysis_data.get("docker_output", ""),
                "etl_output": etl_output,
                "history": history,
            },
        )
    except Exception as e:
        Logger.log(f"Ошибка при получении страницы анализа: {str(e)}")
        return RedirectResponse(url="/main")
