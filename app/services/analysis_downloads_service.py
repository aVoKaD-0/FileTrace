import os
import uuid

from fastapi import Request
from fastapi.responses import FileResponse, JSONResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.infra.artifacts.analysis_artifacts_repository import AnalysisArtifactsRepository
from app.repositories.analysis_repository import AnalysisRepository
from app.services.audit_service import AuditService
from app.utils.trace_csv_filter import filter_trace_csv_lines


class AnalysisDownloadsService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.analysis_repo = AnalysisRepository(db)
        self.audit = AuditService(db)

    async def download_trace_csv(self, *, analysis_id: str, request: Request):
        csv_file_path = AnalysisArtifactsRepository.get_trace_csv_path(analysis_id)
        if not os.path.exists(csv_file_path):
            return JSONResponse(status_code=404, content={"error": "trace.csv не найден"})

        try:
            analysis_uuid = uuid.UUID(str(analysis_id))
        except Exception:
            return JSONResponse(status_code=400, content={"error": "Некорректный analysis_id"})

        analysis = await self.analysis_repo.get_by_id(analysis_uuid)
        filename = getattr(analysis, "filename", None) if analysis else None

        filtered_lines = filter_trace_csv_lines(csv_file_path, filename)

        await self.audit.log(request=request, event_type="analysis.trace_csv_downloaded", metadata={"analysis_id": analysis_id})
        if filtered_lines is None:
            return FileResponse(path=str(csv_file_path), filename=f"analysis_{analysis_id}_trace.csv", media_type="text/csv")

        return Response(
            content="".join(filtered_lines),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=analysis_{analysis_id}_trace.csv"},
        )

    async def download_clean_tree_csv(self, *, analysis_id: str, request: Request):
        csv_file_path = AnalysisArtifactsRepository.get_clean_tree_csv_path(analysis_id)
        if not os.path.exists(csv_file_path):
            return JSONResponse(status_code=404, content={"error": "clean_tree.csv не найден"})

        await self.audit.log(request=request, event_type="analysis.clean_tree_csv_downloaded", metadata={"analysis_id": analysis_id})
        return FileResponse(path=str(csv_file_path), filename=f"analysis_{analysis_id}_clean_tree.csv", media_type="text/csv")

    async def download_clean_tree_json(self, *, analysis_id: str, request: Request):
        json_file_path = AnalysisArtifactsRepository.get_clean_tree_json_path(analysis_id)
        if not os.path.exists(json_file_path):
            return JSONResponse(status_code=404, content={"error": "clean_tree.json не найден"})

        await self.audit.log(request=request, event_type="analysis.clean_tree_json_downloaded", metadata={"analysis_id": analysis_id})
        return FileResponse(
            path=str(json_file_path),
            filename=f"analysis_{analysis_id}_clean_tree.json",
            media_type="application/json",
        )

    async def download_threat_report(self, *, analysis_id: str, request: Request):
        json_file_path = AnalysisArtifactsRepository.get_threat_report_path(analysis_id)
        if not os.path.exists(json_file_path):
            return JSONResponse(status_code=404, content={"error": "threat_report.json не найден"})

        await self.audit.log(request=request, event_type="analysis.threat_report_downloaded", metadata={"analysis_id": analysis_id})
        return FileResponse(
            path=str(json_file_path),
            filename=f"analysis_{analysis_id}_threat_report.json",
            media_type="application/json",
        )
