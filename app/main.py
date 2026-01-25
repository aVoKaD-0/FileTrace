from fastapi import Request
from fastapi import FastAPI, Depends
from fastapi.staticfiles import StaticFiles
from app.api.main import router as main_router
from app.api.users import router as user_router
from app.api.analysis import router as analysis_router
from app.api.documents import router as documents_router
from app.services.cleanup_service import CleanupService
from app.core.logging import setup_logging
from app.auth.auth import verify_token
from app.lifecycle import build_lifespan
from app.middlewares.request_logging import install_request_logger
from app.middlewares.auth_cookie_gate import install_cookie_auth_gate
from fastapi.responses import HTMLResponse, RedirectResponse
 
 
def create_app() -> FastAPI:
    setup_logging()
    cleanup_service = CleanupService()
    app = FastAPI(lifespan=build_lifespan(cleanup_service))

    app.mount("/static", StaticFiles(directory="app/static"), name="static")
    app.mount("/media", StaticFiles(directory="media"), name="media")

    install_request_logger(app)
    install_cookie_auth_gate(app)

    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc):
        return RedirectResponse(url="/main/")
    
    @app.get("/", response_class=HTMLResponse)
    async def old_root(request: Request):
        return RedirectResponse(url="/main/")

    @app.get("/protected-route")
    async def protected_route(username: str = Depends(verify_token)):
        return {"message": f"Hello, {username}!"}

    app.include_router(user_router)
    app.include_router(analysis_router)
    app.include_router(documents_router)
    app.include_router(main_router)

    return app