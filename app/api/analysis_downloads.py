import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.responses import JSONResponse
from app.infra.db.deps import get_db
from app.services.analysis_downloads_service import AnalysisDownloadsService


router = APIRouter()


@router.get("/download-trace-csv/{analysis_id}")
async def download_trace_csv(analysis_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    try:
        return await AnalysisDownloadsService(db).download_trace_csv(analysis_id=analysis_id, request=request)
    except Exception as e:
        logging.getLogger("app").exception("Ошибка при скачивании trace.csv")
        return JSONResponse(status_code=500, content={"error": f"Ошибка при скачивании trace.csv: {str(e)}"})


@router.get("/download-clean-tree-csv/{analysis_id}")
async def download_clean_tree_csv(analysis_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    try:
        return await AnalysisDownloadsService(db).download_clean_tree_csv(analysis_id=analysis_id, request=request)
    except Exception as e:
        logging.getLogger("app").exception("Ошибка при скачивании clean_tree.csv")
        return JSONResponse(status_code=500, content={"error": f"Ошибка при скачивании clean_tree.csv: {str(e)}"})


@router.get("/download-clean-tree-json/{analysis_id}")
async def download_clean_tree_json(analysis_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    try:
        return await AnalysisDownloadsService(db).download_clean_tree_json(analysis_id=analysis_id, request=request)
    except Exception as e:
        logging.getLogger("app").exception("Ошибка при скачивании clean_tree.json")
        return JSONResponse(status_code=500, content={"error": f"Ошибка при скачивании clean_tree.json: {str(e)}"})


@router.get("/download-threat-report/{analysis_id}")
async def download_threat_report(analysis_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    try:
        return await AnalysisDownloadsService(db).download_threat_report(analysis_id=analysis_id, request=request)
    except Exception as e:
        logging.getLogger("app").exception("Ошибка при скачивании threat_report.json")
        return JSONResponse(status_code=500, content={"error": f"Ошибка при скачивании threat_report.json: {str(e)}"})
