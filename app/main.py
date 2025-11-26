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
    # Функция создания и настройки приложения FastAPI
    # Инициализирует роутеры, middleware, обработчики событий и статические файлы
    # Возвращает:
    #   FastAPI: Настроенное приложение
    setup_logging()
    app = FastAPI()

    # Подключаем статические файлы (CSS, JavaScript, изображения)
    app.mount("/static", StaticFiles(directory="app/static"), name="static")
    # Медиафайлы презентации (PNG, SVG) для главной страницы
    app.mount("/media", StaticFiles(directory="media"), name="media")
    # Инициализация шаблонизатора Jinja2 для рендеринга HTML страниц
    templates = Jinja2Templates(directory="app/templates")

    # Инициализация сервиса очистки (удаляет старые временные файлы и анализы)
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
        # Вызывается при запуске приложения
        # Запускает фоновые задачи, такие как очистка временных файлов
        await cleanup_service.start()

    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc):
        # Обработчик для страниц, которые не найдены (404)
        # Перенаправляет пользователя на главную страницу вместо показа ошибки
        return RedirectResponse(url="/main")

    @app.get("/main", response_class=HTMLResponse)
    async def root(request: Request):
        # Обработчик главной страницы "/"
        # Отображает основную страницу приложения
        return templates.TemplateResponse("main.html", {"request": request})
    
    @app.get("/", response_class=HTMLResponse)
    async def old_root(request: Request):
        return RedirectResponse(url="/main")
    
    @app.get("/protected-route")
    async def protected_route(username: str = Depends(verify_token)):
        # Пример защищенного маршрута, требующего авторизации
        # Зависимость verify_token проверяет JWT токен перед доступом
        return {"message": f"Hello, {username}!"}
    
    @app.middleware("http")
    async def check_token(request: Request, call_next):
        # Middleware для проверки JWT токенов и управления аутентификацией
        # Выполняется для каждого запроса перед вызовом обработчика маршрута
        
        path = request.url.path
        access_token = request.cookies.get("access_token")
        refresh_token = request.cookies.get("refresh_token")
        is_authenticated = bool(access_token or refresh_token)
        
        # Если пользователь авторизован и пытается зайти на страницу логина,
        # перенаправляем его на главную страницу
        if path == "/users/" and is_authenticated:
            return RedirectResponse(url="/main")
            
        # Разрешаем доступ к страницам пользователей, статическим файлам и главной
        # страницы даже без авторизации
        if path.startswith("/static/") or path.startswith("/media/") or path == "/main" or path == "/":
            return await call_next(request)
        if not is_authenticated and path.startswith("/users/"):
            return await call_next(request)
            
        # Если пользователь не авторизован и пытается получить доступ к защищенным
        # страницам, перенаправляем его на страницу входа
        if not is_authenticated:
            return RedirectResponse(url="/users/")
            
        try:
            # Получаем токены из cookies
            access_token = request.cookies.get("access_token")
            refresh_token = request.cookies.get("refresh_token")

            # Если нет ни одного токена, перенаправляем на страницу входа
            if not access_token and not refresh_token:
                return RedirectResponse(url="/users/")

            # Если есть refresh_token, всегда проверяем его первым
            if refresh_token:
                async with AsyncSessionLocal() as db2:
                    user_service = UserService(db2)
                    user = await user_service.get_refresh_token(refresh_token=refresh_token)
                    if user is None:
                        # Если refresh_token отсутствует в базе, очищаем куки и перенаправляем на страницу входа
                        response = RedirectResponse(url="/users/")
                        response.delete_cookie(key="refresh_token")
                        response.delete_cookie(key="access_token")
                        return response

                    # Проверяем валидность самого refresh_token как JWT
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

                    # На этом этапе refresh_token валиден, пользователь существует
                    # Проверяем access_token и при необходимости создаём новый
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

                    # refresh_token и access_token валидны, просто пропускаем запрос дальше
                    return await call_next(request)

            # Если refresh_token нет, но есть access_token, проверяем только его
            try:
                jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
            except JWTError:
                response = RedirectResponse(url="/users/")
                response.delete_cookie(key="access_token")
                return response

            return await call_next(request)

        except Exception as e:
            # В случае любой ошибки при проверке токенов, перенаправляем на страницу входа
            return RedirectResponse(url="/users/")
            
        # Если проверка токенов прошла успешно, продолжаем выполнение запроса
        response = await call_next(request)
        return response

    # Подключаем роутеры с эндпоинтами для различных модулей
    app.include_router(user_router)       # Маршруты для управления пользователями
    app.include_router(analysis_router)   # Маршруты для анализа файлов
    app.include_router(main_router)       # Основные маршруты приложения

    @app.on_event("shutdown")
    async def shutdown_event():
        # Вызывается при остановке приложения
        # Останавливает фоновые задачи и освобождает ресурсы
        await cleanup_service.stop()

    return app