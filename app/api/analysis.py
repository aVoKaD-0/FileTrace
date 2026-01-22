from fastapi import APIRouter
from fastapi.staticfiles import StaticFiles

from app.api.analysis_pages import router as analysis_pages_router
from app.api.analysis_rest import router as analysis_rest_router
from app.api.analysis_ws import router as analysis_ws_router
from app.api.analysis_downloads import router as analysis_downloads_router

router = APIRouter(prefix="/analysis", tags=["analysis"])
router.mount("/static", StaticFiles(directory="app/static"), name="static")

router.include_router(analysis_pages_router)
router.include_router(analysis_rest_router)
router.include_router(analysis_ws_router)
router.include_router(analysis_downloads_router)

# Endpoints were split into dedicated modules.
