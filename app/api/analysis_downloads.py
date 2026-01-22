import os

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse, JSONResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.repositories.analysis_artifacts_repository import AnalysisArtifactsRepository
from app.services.audit_service import AuditService
from app.services.user_service import UserService
from app.utils.logging import Logger


router = APIRouter()


@router.get("/download-trace-csv/{analysis_id}")
async def download_trace_csv(analysis_id: str, db: AsyncSession = Depends(get_db)):
    try:
        csv_file_path = AnalysisArtifactsRepository.get_trace_csv_path(analysis_id)

        if not os.path.exists(csv_file_path):
            return JSONResponse(status_code=404, content={"error": "trace.csv не найден"})

        userservice = UserService(db)
        result_data = await userservice.get_result_data(str(analysis_id))
        target_exe = (result_data or {}).get("filename")
        target_exe_lower = (target_exe or "").lower()
        target_exe_lower_no_ext = target_exe_lower[:-4] if target_exe_lower.endswith(".exe") else target_exe_lower

        filtered_lines = []
        with open(csv_file_path, "r", encoding="utf-8", errors="ignore") as f:
            header = f.readline()
            if header:
                filtered_lines.append(header)

            found = False
            for line in f:
                if not found and target_exe_lower:
                    l = line.lower()
                    if (
                        ("," + target_exe_lower + ",") in l
                        or ("\\" + target_exe_lower) in l
                        or ("\\" + target_exe_lower_no_ext + ".exe") in l
                        or (" " + target_exe_lower) in l
                        or (" " + target_exe_lower_no_ext) in l
                    ):
                        found = True

                if found or not target_exe_lower:
                    filtered_lines.append(line)

        if target_exe_lower and len(filtered_lines) <= 1:
            filtered_lines = None

        await AuditService(db).log(request=None, event_type="analysis.trace_csv_downloaded", metadata={"analysis_id": analysis_id})
        if filtered_lines is None:
            return FileResponse(path=str(csv_file_path), filename=f"analysis_{analysis_id}_trace.csv", media_type="text/csv")

        return Response(
            content="".join(filtered_lines),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=analysis_{analysis_id}_trace.csv"},
        )
    except Exception as e:
        Logger.log(f"Ошибка при скачивании trace.csv: {str(e)}")
        return JSONResponse(status_code=500, content={"error": f"Ошибка при скачивании trace.csv: {str(e)}"})


@router.get("/download-clean-tree-csv/{analysis_id}")
async def download_clean_tree_csv(analysis_id: str, db: AsyncSession = Depends(get_db)):
    try:
        csv_file_path = AnalysisArtifactsRepository.get_clean_tree_csv_path(analysis_id)

        if not os.path.exists(csv_file_path):
            return JSONResponse(status_code=404, content={"error": "clean_tree.csv не найден"})

        await AuditService(db).log(request=None, event_type="analysis.clean_tree_csv_downloaded", metadata={"analysis_id": analysis_id})
        return FileResponse(path=str(csv_file_path), filename=f"analysis_{analysis_id}_clean_tree.csv", media_type="text/csv")
    except Exception as e:
        Logger.log(f"Ошибка при скачивании clean_tree.csv: {str(e)}")
        return JSONResponse(status_code=500, content={"error": f"Ошибка при скачивании clean_tree.csv: {str(e)}"})


@router.get("/download-clean-tree-json/{analysis_id}")
async def download_clean_tree_json(analysis_id: str, db: AsyncSession = Depends(get_db)):
    try:
        json_file_path = AnalysisArtifactsRepository.get_clean_tree_json_path(analysis_id)

        if not os.path.exists(json_file_path):
            return JSONResponse(status_code=404, content={"error": "clean_tree.json не найден"})

        await AuditService(db).log(request=None, event_type="analysis.clean_tree_json_downloaded", metadata={"analysis_id": analysis_id})
        return FileResponse(
            path=str(json_file_path),
            filename=f"analysis_{analysis_id}_clean_tree.json",
            media_type="application/json",
        )
    except Exception as e:
        Logger.log(f"Ошибка при скачивании clean_tree.json: {str(e)}")
        return JSONResponse(status_code=500, content={"error": f"Ошибка при скачивании clean_tree.json: {str(e)}"})


@router.get("/download-threat-report/{analysis_id}")
async def download_threat_report(analysis_id: str, db: AsyncSession = Depends(get_db)):
    try:
        json_file_path = AnalysisArtifactsRepository.get_threat_report_path(analysis_id)

        if not os.path.exists(json_file_path):
            return JSONResponse(status_code=404, content={"error": "threat_report.json не найден"})

        await AuditService(db).log(request=None, event_type="analysis.threat_report_downloaded", metadata={"analysis_id": analysis_id})
        return FileResponse(
            path=str(json_file_path),
            filename=f"analysis_{analysis_id}_threat_report.json",
            media_type="application/json",
        )
    except Exception as e:
        Logger.log(f"Ошибка при скачивании threat_report.json: {str(e)}")
        return JSONResponse(status_code=500, content={"error": f"Ошибка при скачивании threat_report.json: {str(e)}"})
