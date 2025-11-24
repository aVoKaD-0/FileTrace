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
        return RedirectResponse(url="/")

    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request):
        # Обработчик главной страницы "/"
        # Отображает основную страницу приложения
        return templates.TemplateResponse("main.html", {"request": request})
    
    @app.get("/protected-route")
    async def protected_route(username: str = Depends(verify_token)):
        # Пример защищенного маршрута, требующего авторизации
        # Зависимость verify_token проверяет JWT токен перед доступом
        return {"message": f"Hello, {username}!"}
    
    @app.middleware("http")
    async def check_token(request: Request, call_next):
        # Middleware для проверки JWT токенов и управления аутентификацией
        # Выполняется для каждого запроса перед вызовом обработчика маршрута
        
        # Если пользователь авторизован и пытается зайти на страницу логина,
        # перенаправляем его на страницу анализов
        if (request.url.path == "/users/" and request.cookies.get("access_token") and request.cookies.get("refresh_token")):
            return RedirectResponse(url="/analysis/")
            
        # Разрешаем доступ к страницам пользователей, статическим файлам и главной
        # страницы даже без авторизации
        if (request.url.path.startswith("/users/") and not request.cookies.get("access_token") and not request.cookies.get("refresh_token")) or request.url.path.startswith("/static/") or request.url.path == "/":
            return await call_next(request)
            
        # Если пользователь не авторизован и пытается получить доступ к защищенным
        # страницам, перенаправляем его на страницу входа
        if not request.cookies.get("access_token") and not request.cookies.get("refresh_token") and not request.url.path.startswith("/users/") and not request.url.path.startswith("/static/") and request.url.path != "/":
            return RedirectResponse(url="/users/")
            
        try:
            # Получаем токены из cookies
            access_token = request.cookies.get("access_token")
            refresh_token = request.cookies.get("refresh_token")
            
            # Если нет ни одного токена, перенаправляем на страницу входа
            if not access_token and not refresh_token:
                return RedirectResponse(url="/users/")
                
            # Если есть только refresh_token, создаем новый access_token
            elif refresh_token and not access_token:
                async with AsyncSessionLocal() as db2:
                    # Проверяем, действителен ли refresh_token
                    user_service = UserService(db2)
                    user = await user_service.get_refresh_token(refresh_token=refresh_token)
                    if user is None:
                        # Если refresh_token недействителен, удаляем его и перенаправляем
                        response.cookies.delete("refresh_token")
                        return RedirectResponse(url="/users/")
                        
                    # Создаем новый access_token на основе данных из refresh_token
                    access_token = create_access_token({"sub": jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM]).get("sub")})
                    response = await call_next(request)
                    
                    # Устанавливаем новый access_token в cookies
                    response.set_cookie(
                        key="access_token",
                        value=access_token,
                        httponly=True,
                        samesite="Lax",
                        max_age=30*60,
                        secure=True
                    )
                    return response
                    
            try:
                # Декодируем и проверяем access_token
                payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
                username = payload.get("sub")
                if not username:
                    return RedirectResponse(url="/users/")
            except JWTError as e:
                # Если токен недействителен, перенаправляем на страницу входа
                return RedirectResponse(url="/users/")
                
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