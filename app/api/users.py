from fastapi import Response
from fastapi.staticfiles import StaticFiles
from app.core.security import verify_password
from app.core.db import get_db
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.security import OAuth2PasswordBearer
from app.services.user_service import UserService
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
import uuid
from app.auth.auth import send_email, create_access_token, create_refresh_token, generate_code, send_reset_password_email, uuid_by_token
from app.services.audit_service import AuditService
from app.schemas.users import EmailConfirmation, UserLogin, UserRegistration, UserPasswordReset, ForgotPasswordRequest
from app.core.crypto import decrypt_str


router = APIRouter(prefix="/users", tags=["users"])

router.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

@router.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("user.html", {"request": request})

@router.post("/registration")
async def register_user(request: Request, response: Response, user_data: UserRegistration, db: AsyncSession = Depends(get_db)):
    try:
        from app.utils.captcha import captcha
        is_captcha_valid = captcha.verify_captcha(user_data.captcha_id, user_data.captcha_text)
        
        if not is_captcha_valid:
            return JSONResponse(
                status_code=400,
                content={"detail": "Неверный код с картинки. Пожалуйста, попробуйте еще раз."}
            )
        
        user_service = UserService(db)
        
        existing_user = await user_service.get_by_email(user_data.email)
        if existing_user:
            return JSONResponse(
                status_code=400,
                content={"detail": "Пользователь с таким email уже существует"}
            )
        
        user_id, confirm_code = await user_service.create_user(user_data.email, user_data.password)
        await send_email(email=user_data.email, verification_code=f"{confirm_code}")
        await AuditService(db).log(request=request, event_type="user.registered", user_id=str(user_id), metadata={"email": user_data.email})
        response.set_cookie(key="user_id", value=str(user_id), httponly=True, max_age=30*60, samesite="Lax", secure=True)
        return {"message": "Пользователь успешно зарегистрирован"}
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": f"Ошибка при регистрации: {str(e)}"}
        )

@router.get("/confirm-email", response_class=HTMLResponse)
async def confirm_email_page(request: Request, db: AsyncSession = Depends(get_db)):
    # Страница подтверждения email
    # Отображает форму для ввода кода подтверждения и маскированный email
    user_id = request.cookies.get("user_id")
    masked_email = None
    if user_id:
        try:
            userservice = UserService(db)
            user = await userservice.get_user_by_id(uuid.UUID(str(user_id)))
            if user and user.email_encrypted:
                email = decrypt_str(user.email_encrypted)
                # простое маскирование email
                local, _, domain = email.partition("@")
                if domain:
                    masked_local = (local[0] + "***" + (local[-1] if len(local) > 1 else "")) if local else "***"
                    parts = domain.split(".")
                    masked_domain = (parts[0][0] + "***") if parts and parts[0] else "***"
                    if len(parts) > 1:
                        masked_domain = masked_domain + "." + parts[-1]
                    masked_email = f"{masked_local}@{masked_domain}"
        except Exception:
            masked_email = None
    else:
        return RedirectResponse(url="/users", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("confirm_email.html", {"request": request, "masked_email": masked_email, "user_id": user_id})

@router.post("/confirm")
async def confirm_email(request: Request, response: Response, data: EmailConfirmation, db: AsyncSession = Depends(get_db)):
    # Обработчик подтверждения email
    # Проверяет код подтверждения и активирует аккаунт
    userservice = UserService(db)
    user_id = uuid.UUID(str(data.user_id))
    user = await userservice.get_user_by_id(user_id)
    if user and data.code == user.confirmation_code:
        # Код верный, подтверждаем пользователя
        user.confirmed = True
        user.confirmation_code = None
        
        # Создаем токены авторизации
        access_token = create_access_token({"sub": str(user.id)})
        refresh_token = create_refresh_token({"sub": str(user.id)})
        
        # Сохраняем refresh токен и устанавливаем куки
        await userservice.update_refresh_token_by_user_id(user.id, refresh_token)
        response.set_cookie(key="access_token", value=access_token, httponly=True, max_age=30*60, samesite="Lax", secure=True)
        response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, max_age=7*24*60*60, samesite="Lax", secure=True)
        await userservice.__commit__()
        # Аудит подтверждения email
        await AuditService(db).log(request=request, event_type="user.email_confirmed", user_id=str(user.id))
        return {"message": "Email confirmed"}
    
    # Неверный код подтверждения
    # Аудит неуспешного подтверждения
    await AuditService(db).log(request=request, event_type="user.email_confirm_failed", user_id=str(data.user_id))
    raise HTTPException(status_code=400, detail="Invalid code")

# Схема для OAuth2 авторизации
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@router.post("/login")
async def login(request: Request, response: Response, user_data: UserLogin, db: AsyncSession = Depends(get_db)):
    # Обработчик входа пользователя в систему
    # Проверяет учетные данные, капчу и создает токены авторизации
    try:
        # Проверяем капчу, если она предоставлена
        if user_data.captcha_id and user_data.captcha_text:
            from app.utils.captcha import captcha
            is_captcha_valid = captcha.verify_captcha(user_data.captcha_id, user_data.captcha_text)
            
            if not is_captcha_valid:
                await AuditService(db).log(request=request, event_type="auth.captcha_required", metadata={"email": user_data.email})
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Неверный код с картинки. Пожалуйста, попробуйте еще раз."}
                )
        else:
            await AuditService(db).log(request=request, event_type="auth.captcha_required", metadata={"email": user_data.email})
            return JSONResponse(
                status_code=400,
                content={"detail": "Пожалуйста, введите код с картинки."}
            )
        
        user_service = UserService(db)
        
        # Проверяем количество неудачных попыток входа
        login_attempts = await user_service.get_login_attempts(user_data.email)
        
        # Если уже было 3 или более неудачных попыток, и капча не предоставлена
        if login_attempts >= 3 and (not user_data.captcha_id or not user_data.captcha_text):
            return JSONResponse(
                status_code=400,
                content={
                    "detail": "Превышено количество попыток входа. Пожалуйста, введите код с картинки.",
                    "require_captcha": True
                }
            )
        
        # Проверяем учетные данные пользователя
        user = await user_service.authenticate_user(user_data.email, user_data.password)
        
        if not user:
            # Увеличиваем счетчик неудачных попыток входа
            await user_service.increment_login_attempts(user_data.email)
            
            # Проверяем, требуется ли капча для следующей попытки
            login_attempts = await user_service.get_login_attempts(user_data.email)
            
            if login_attempts >= 3:
                # Если попыток больше 3, требуем капчу
                await AuditService(db).log(request=request, event_type="auth.login_failed", metadata={"email": user_data.email, "reason": "invalid_credentials", "captcha_required": True})
                return JSONResponse(
                    status_code=400,
                    content={
                        "detail": "Неверный email или пароль",
                        "require_captcha": True
                    }
                )
            
            # Обычная ошибка авторизации
            await AuditService(db).log(request=request, event_type="auth.login_failed", metadata={"email": user_data.email, "reason": "invalid_credentials"})
            return JSONResponse(
                status_code=400,
                content={"detail": "Неверный email или пароль"}
            )
        
        # Сбрасываем счетчик неудачных попыток входа
        await user_service.reset_login_attempts(user_data.email)
        
        # Генерируем токены авторизации
        access_token = create_access_token(data={"sub": str(user.id)})
        refresh_token = create_refresh_token(data={"sub": str(user.id)})
        
        # Сохраняем refresh_token в базе данных
        await user_service.update_refresh_token_by_user_id(user.id, refresh_token)
        
        # Устанавливаем cookie с токенами
        response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, max_age=30*60)
        response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=True, max_age=7*24*60*60)
        
        await AuditService(db).log(request=request, event_type="auth.login_success", user_id=str(user.id), metadata={"email": user_data.email})
        return {"message": "Вход выполнен успешно"}
    except Exception as e:
        # Обработка ошибок при входе
        await AuditService(db).log(request=request, event_type="error.app_exception", metadata={"route": "users.login", "error": str(e)})
        return JSONResponse(
            status_code=500,
            content={"detail": f"Ошибка при входе: {str(e)}"}
        )

@router.get("/captcha")
async def generate_captcha():
    # Генерирует новую капчу
    # Возвращает идентификатор капчи и изображение в формате base64
    from app.utils.captcha import captcha
    return captcha.generate_captcha()

@router.post("/logout")
async def logout(response: Response, request: Request, db: AsyncSession = Depends(get_db)):
    # Обработчик выхода из системы
    # Удаляет токены и очищает куки
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")
    
    # Если есть хотя бы один токен в куках
    if (access_token and refresh_token) or (refresh_token and not access_token):
        user_service = UserService(db)
        user = await user_service.get_refresh_token(refresh_token=refresh_token)
        
        if user is None:
            return {"message": "Logout successful"}
            
        # Удаляем refresh токен из базы
        await user_service.update_refresh_token_by_user_id(user.id, None)
        
        # Удаляем куки
        if access_token:
            response.delete_cookie(key="access_token", httponly=True)
        response.delete_cookie(key="refresh_token", httponly=True)
    else:
        return RedirectResponse(url="/users/")
        
    return {"message": "Logout successful"}

@router.post("/resend-code")
async def reset_code_page(request: Request, db: AsyncSession = Depends(get_db)):
    # Повторная отправка кода подтверждения
    # Генерирует новый код и отправляет его на email
    user_id = request.query_params.get("user_id")
    if not user_id:
        return JSONResponse(status_code=400, content={"detail": "user_id is required"})

    userservice = UserService(db)
    user = await userservice.get_user_by_id(uuid.UUID(str(user_id)))
    
    # Генерируем новый код
    confirmation_code = generate_code()
    user.confirmation_code = confirmation_code
    await userservice.__commit__()
    
    # Отправляем код на email
    await send_email(decrypt_str(user.email_encrypted), f"Confirmation code: {confirmation_code}")
    await AuditService(db).log(request=request, event_type="user.confirmation_resent", user_id=str(user.id))
    return JSONResponse(content={"message": "Email sent"})

@router.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})


@router.post("/forgot-password")
async def forgot_password(request: Request, data: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    try:
        from app.utils.captcha import captcha
        is_captcha_valid = captcha.verify_captcha(data.captcha_id, data.captcha_text)

        if not is_captcha_valid:
            return JSONResponse(
                status_code=400,
                content={"detail": "Неверный код с картинки. Пожалуйста, попробуйте еще раз."}
            )

        user_service = UserService(db)
        user = await user_service.get_by_email(data.email)

        # Не раскрываем, существует ли email, возвращаем одинаковый ответ
        if not user:
            await AuditService(db).log(request=request, event_type="user.password_reset_requested", metadata={"email": data.email, "found": False})
            return {"message": "Если пользователь с таким email существует, на него отправлено письмо со ссылкой для сброса пароля."}

        email_plain = decrypt_str(user.email_encrypted)
        reset_token = create_access_token({"sub": str(user.id)})
        reset_link = str(request.url_for("reset_password")) + f"?token={reset_token}"

        await send_reset_password_email(email_plain, reset_link)
        await AuditService(db).log(request=request, event_type="user.password_reset_requested", user_id=str(user.id), metadata={"email": data.email, "found": True})

        return {"message": "Письмо со ссылкой для сброса пароля отправлено, проверьте вашу почту."}
    except Exception as e:
        await AuditService(db).log(request=request, event_type="error.app_exception", metadata={"route": "users.forgot_password", "error": str(e)})
        return JSONResponse(
            status_code=500,
            content={"detail": f"Ошибка при запросе сброса пароля: {str(e)}"}
        )


@router.get("/reset-password", response_class=HTMLResponse)
async def reset_password(request: Request, response: Response, token: str | None = None, db: AsyncSession = Depends(get_db)):
    # Страница сброса пароля
    # Проверяет наличие токена сброса или refresh токена и определяет тип формы для отображения
    reset_token = token
    refresh_token = request.cookies.get("refresh_token")

    has_token = False

    if reset_token:
        # Сброс по ссылке из письма
        has_token = True
    elif refresh_token:
        # Пользователь авторизован, проверяем refresh токен
        userservice = UserService(db)
        user = await userservice.get_refresh_token(refresh_token=refresh_token)
        if user is None:
            # Если токен недействителен, удаляем его
            response.cookies.delete("refresh_token")
            return RedirectResponse(url="/users/")
        has_token = True

    return templates.TemplateResponse(
        "reset_password.html",
        {"request": request, "has_token": has_token, "reset_token": reset_token}
    )


@router.post("/reset-password")
async def reset_password(request: Request, user_data: UserPasswordReset, db: AsyncSession = Depends(get_db)):
    # Обработчик сброса пароля
    # Проверяет капчу, токен сброса или refresh токен и обновляет пароль пользователя
    try:
        # Проверяем капчу для защиты от автоматизированного перебора
        from app.utils.captcha import captcha
        is_captcha_valid = captcha.verify_captcha(user_data.captcha_id, user_data.captcha_text)

        if not is_captcha_valid:
            return JSONResponse(
                status_code=400,
                content={"detail": "Неверный код с картинки. Пожалуйста, попробуйте еще раз."}
            )

        user_service = UserService(db)
        refresh_token = request.cookies.get("refresh_token")

        # Приоритет: токен из письма для незалогиненного пользователя
        if user_data.reset_token:
            try:
                user_id_str = uuid_by_token(user_data.reset_token)
                user_id = uuid.UUID(str(user_id_str))
            except Exception:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Ссылка для сброса пароля недействительна или устарела."}
                )

            user = await user_service.get_user_by_id(user_id)
            if user is None:
                return JSONResponse(
                    status_code=404,
                    content={"detail": "Пользователь не найден"}
                )

            from app.core.security import get_password_hash
            user.hashed_password = get_password_hash(user_data.password)
            user.login_attempts = 0
            db.add(user)
            await db.commit()
        elif refresh_token:
            # Пользователь авторизован, используем его токен для сброса
            user = await user_service.update_password(refresh_token=refresh_token, password=user_data.password)
            if user is None:
                return JSONResponse(
                    status_code=404,
                    content={"detail": "Пользователь не найден"}
                )
        else:
            return JSONResponse(
                status_code=400,
                content={"detail": "Токен сброса пароля недействителен или отсутствует."}
            )

        await AuditService(db).log(request=request, event_type="user.password_changed", metadata={"by": "reset_password"})
        return {"message": "Пароль успешно обновлен"}
    except Exception as e:
        # Обработка ошибок при сбросе пароля
        await AuditService(db).log(request=request, event_type="error.app_exception", metadata={"route": "users.reset_password", "error": str(e)})
        return JSONResponse(
            status_code=500,
            content={"detail": f"Ошибка при сбросе пароля: {str(e)}"}
        )