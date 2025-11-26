from jose import jwt
from fastapi import Request
from fastapi import FastAPI, Depends
from jose.exceptions import JWTError
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from app.api.main import router as main_router
from app.api.users import router as user_router
from app.config.auth import SECRET_KEY, ALGORITHM
from app.services.user_service import UserService
from app.api.analysis import router as analysis_router
from app.services.cleanup_service import CleanupService
from app.core.db import AsyncSessionLocal
from app.core.logging import setup_logging, set_request_id, clear_request_id
from app.auth.auth import verify_token, create_access_token
from fastapi.responses import HTMLResponse, RedirectResponse
import logging
import time

def create_app() -> FastAPI:
    setup_logging()
    app = FastAPI()

    app.mount("/static", StaticFiles(directory="app/static"), name="static")
    app.mount("/media", StaticFiles(directory="media"), name="media")
    templates = Jinja2Templates(directory="app/templates")

    cleanup_service = CleanupService()

    @app.middleware("http")
    async def request_logger(request: Request, call_next):
        rid = set_request_id(request.headers.get("X-Request-ID"))
        start = time.perf_counter()
        logger = logging.getLogger("app")
        try:
            logger.info(f"{request.method} {request.url.path} started")
            response = await call_next(request)
            duration_ms = (time.perf_counter() - start) * 1000
            response.headers["X-Request-ID"] = rid
            logger.info(f"{request.method} {request.url.path} {response.status_code} {duration_ms:.1f}ms")
            return response
        except Exception:
            duration_ms = (time.perf_counter() - start) * 1000
            logger.exception(f"Unhandled error {request.method} {request.url.path} {duration_ms:.1f}ms")
            raise
        finally:
            clear_request_id()

    @app.on_event("startup")
    async def startup_event():
        await cleanup_service.start()

    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc):
        return RedirectResponse(url="/main")

    @app.get("/main", response_class=HTMLResponse)
    async def root(request: Request):
        return templates.TemplateResponse("main.html", {"request": request})
    
    @app.get("/", response_class=HTMLResponse)
    async def old_root(request: Request):
        return RedirectResponse(url="/main")
    
    @app.get("/protected-route")
    async def protected_route(username: str = Depends(verify_token)):
        return {"message": f"Hello, {username}!"}
    
    @app.middleware("http")
    async def check_token(request: Request, call_next):
        
        path = request.url.path
        access_token = request.cookies.get("access_token")
        refresh_token = request.cookies.get("refresh_token")
        is_authenticated = bool(access_token or refresh_token)
        
        if path == "/users/" and is_authenticated:
            return RedirectResponse(url="/main")
            
        if path.startswith("/static/") or path.startswith("/media/") or path == "/main" or path == "/":
            return await call_next(request)
        if not is_authenticated and path.startswith("/users/"):
            return await call_next(request)
            
        if not is_authenticated:
            return RedirectResponse(url="/users/")
            
        try:
            access_token = request.cookies.get("access_token")
            refresh_token = request.cookies.get("refresh_token")

            if not access_token and not refresh_token:
                return RedirectResponse(url="/users/")

            if refresh_token:
                async with AsyncSessionLocal() as db2:
                    try:
                        user_service = UserService(db2)
                        user = await user_service.get_refresh_token(refresh_token=refresh_token)
                        if user is None:
                            response = RedirectResponse(url="/users/")
                            response.delete_cookie(key="refresh_token")
                            response.delete_cookie(key="access_token")
                            return response
                    except:
                        response = await call_next(request)
                        response.delete_cookie(key="refresh_token")
                        response.delete_cookie(key="access_token")
                        return response

                    try:
                        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
                        user_id = payload.get("sub")
                        if not user_id:
                            response = RedirectResponse(url="/users/")
                            response.delete_cookie(key="refresh_token")
                            response.delete_cookie(key="access_token")
                            return response
                    except JWTError:
                        response = RedirectResponse(url="/users/")
                        response.delete_cookie(key="refresh_token")
                        response.delete_cookie(key="access_token")
                        return response

                    needs_new_access = False
                    if not access_token:
                        needs_new_access = True
                    else:
                        try:
                            jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
                        except JWTError:
                            needs_new_access = True

                    if needs_new_access:
                        new_access_token = create_access_token({"sub": user_id})
                        response = await call_next(request)
                        response.set_cookie(
                            key="access_token",
                            value=new_access_token,
                            httponly=True,
                            samesite="Lax",
                            max_age=30*60,
                            secure=True
                        )
                        return response

                    return await call_next(request)

            try:
                jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
            except JWTError:
                response = RedirectResponse(url="/users/")
                response.delete_cookie(key="access_token")
                return response

            return await call_next(request)

        except Exception as e:
            return RedirectResponse(url="/users/")
            
        response = await call_next(request)
        return response

    app.include_router(user_router)
    app.include_router(analysis_router)
    app.include_router(main_router)

    @app.on_event("shutdown")
    async def shutdown_event():
        await cleanup_service.stop()

    return app