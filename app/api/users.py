from fastapi import Response
from fastapi.staticfiles import StaticFiles
from app.core.security import verify_password
from app.infra.db.deps import get_db
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.security import OAuth2PasswordBearer
from app.services.user_service import UserService
from fastapi import APIRouter, HTTPException, Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
import uuid
from app.auth.auth import send_email, create_access_token, create_refresh_token, generate_code, send_reset_password_email, uuid_by_token
from app.services.audit_service import AuditService
from app.schemas.users import EmailConfirmation, UserLogin, UserRegistration, UserPasswordReset, ForgotPasswordRequest
from app.core.crypto import decrypt_str
from jose import jwt
from jose.exceptions import JWTError
from app.config.auth import SECRET_KEY, ALGORITHM

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
        resp = JSONResponse(status_code=200, content={"detail": "Пользователь успешно зарегистрирован"})
        resp.set_cookie(
            key="user_id",
            value=str(user_id),
            httponly=True,
            max_age=30 * 60,
            samesite="Lax",
            secure=(request.url.scheme == "https"),
            path="/",
        )
        return resp
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": f"Ошибка при регистрации: {str(e)}"}
        )

@router.get("/confirm-email", response_class=HTMLResponse)
async def confirm_email_page(request: Request, db: AsyncSession = Depends(get_db)):
    user_id = request.cookies.get("user_id")
    masked_email = None
    if user_id:
        try:
            userservice = UserService(db)
            user = await userservice.get_user_by_id(uuid.UUID(str(user_id)))
            if user and user.email_encrypted:
                email = decrypt_str(user.email_encrypted)
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
    userservice = UserService(db)
    user_id = uuid.UUID(str(data.user_id))
    user = await userservice.get_user_by_id(user_id)
    if user and data.code == user.confirmation_code:
        user.confirmed = True
        user.confirmation_code = None
        
        access_token = create_access_token({"sub": str(user.id)})
        refresh_token = create_refresh_token({"sub": str(user.id)})
        
        await userservice.update_refresh_token_by_user_id(user.id, refresh_token)
        resp = JSONResponse(status_code=200, content={"message": "Email confirmed"})
        resp.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            max_age=30 * 60,
            samesite="Lax",
            secure=(request.url.scheme == "https"),
            path="/",
        )
        resp.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            max_age=7 * 24 * 60 * 60,
            samesite="Lax",
            secure=(request.url.scheme == "https"),
            path="/",
        )
        await userservice.__commit__()
        await AuditService(db).log(request=request, event_type="user.email_confirmed", user_id=str(user.id))
        return resp
    
    await AuditService(db).log(request=request, event_type="user.email_confirm_failed", user_id=str(data.user_id))
    raise HTTPException(status_code=400, detail="Invalid code")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@router.post("/login")
async def login(request: Request, response: Response, user_data: UserLogin, db: AsyncSession = Depends(get_db)):
    try:
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
        
        login_attempts = await user_service.get_login_attempts(user_data.email)
        
        if login_attempts >= 3 and (not user_data.captcha_id or not user_data.captcha_text):
            return JSONResponse(
                status_code=400,
                content={
                    "detail": "Превышено количество попыток входа. Пожалуйста, введите код с картинки.",
                    "require_captcha": True
                }
            )
        
        user = await user_service.authenticate_user(user_data.email, user_data.password)
        
        if not user:
            await user_service.increment_login_attempts(user_data.email)
            
            login_attempts = await user_service.get_login_attempts(user_data.email)
            
            if login_attempts >= 3:
                await AuditService(db).log(request=request, event_type="auth.login_failed", metadata={"email": user_data.email, "reason": "invalid_credentials", "captcha_required": True})
                return JSONResponse(
                    status_code=400,
                    content={
                        "detail": "Неверный email или пароль",
                        "require_captcha": True
                    }
                )
            
            await AuditService(db).log(request=request, event_type="auth.login_failed", metadata={"email": user_data.email, "reason": "invalid_credentials"})
            return JSONResponse(
                status_code=400,
                content={"detail": "Неверный email или пароль"}
            )
        
        await user_service.reset_login_attempts(user_data.email)
        
        access_token = create_access_token(data={"sub": str(user.id)})
        refresh_token = create_refresh_token(data={"sub": str(user.id)})
        
        await user_service.update_refresh_token_by_user_id(user.id, refresh_token)
        
        await AuditService(db).log(request=request, event_type="auth.login_success", user_id=str(user.id), metadata={"email": user_data.email})
        resp = JSONResponse(status_code=200, content={"message": "Вход выполнен успешно"})
        resp.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=(request.url.scheme == "https"),
            max_age=30 * 60,
            samesite="Lax",
            path="/",
        )
        resp.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=(request.url.scheme == "https"),
            max_age=7 * 24 * 60 * 60,
            samesite="Lax",
            path="/",
        )
        return resp
    except Exception as e:
        await AuditService(db).log(request=request, event_type="error.app_exception", metadata={"route": "users.login", "error": str(e)})
        return JSONResponse(
            status_code=500,
            content={"detail": f"Ошибка при входе: {str(e)}"}
        )

@router.post("/refresh")
async def refresh(request: Request, db: AsyncSession = Depends(get_db)):
    refresh_token_cookie = request.cookies.get("refresh_token")
    if not refresh_token_cookie:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token отсутствует")

    try:
        payload = jwt.decode(refresh_token_cookie, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Некорректный refresh token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token недействителен или истек")

    user_service = UserService(db)
    user = await user_service.get_refresh_token(refresh_token=refresh_token_cookie)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token не найден")

    new_access_token = create_access_token({"sub": str(user.id)})
    new_refresh_token = create_refresh_token({"sub": str(user.id)})
    await user_service.update_refresh_token_by_user_id(user.id, new_refresh_token)

    resp = JSONResponse(status_code=200, content={"message": "Token refreshed"})
    resp.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=(request.url.scheme == "https"),
        max_age=30 * 60,
        samesite="Lax",
        path="/",
    )
    resp.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=(request.url.scheme == "https"),
        max_age=7 * 24 * 60 * 60,
        samesite="Lax",
        path="/",
    )
    return resp

@router.get("/captcha")
async def generate_captcha():
    from app.utils.captcha import captcha
    return captcha.generate_captcha()

@router.post("/logout")
async def logout(response: Response, request: Request, db: AsyncSession = Depends(get_db)):
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")
    
    if (access_token and refresh_token) or (refresh_token and not access_token):
        user_service = UserService(db)
        user = await user_service.get_refresh_token(refresh_token=refresh_token)
        
        if user is None:
            resp = JSONResponse(content={"message": "Logout successful"})
            resp.delete_cookie(key="access_token", path="/")
            resp.delete_cookie(key="refresh_token", path="/")
            return resp
            
        await user_service.update_refresh_token_by_user_id(user.id, None)

        resp = JSONResponse(content={"message": "Logout successful"})
        resp.delete_cookie(key="access_token", path="/")
        resp.delete_cookie(key="refresh_token", path="/")
        return resp
    else:
        return RedirectResponse(url="/main/")

@router.post("/resend-code")
async def reset_code_page(request: Request, db: AsyncSession = Depends(get_db)):
    user_id = request.query_params.get("user_id")
    if not user_id:
        return JSONResponse(status_code=400, content={"detail": "user_id is required"})

    userservice = UserService(db)
    user = await userservice.get_user_by_id(uuid.UUID(str(user_id)))
    
    confirmation_code = generate_code()
    user.confirmation_code = confirmation_code
    await userservice.__commit__()
    
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
    reset_token = token
    refresh_token = request.cookies.get("refresh_token")

    has_token = False

    if reset_token:
        has_token = True
    elif refresh_token:
        userservice = UserService(db)
        user = await userservice.get_refresh_token(refresh_token=refresh_token)
        if user is None:
            response.cookies.delete("refresh_token")
            return RedirectResponse(url="/users/")
        has_token = True

    return templates.TemplateResponse(
        "reset_password.html",
        {"request": request, "has_token": has_token, "reset_token": reset_token}
    )


@router.post("/reset-password")
async def reset_password(request: Request, user_data: UserPasswordReset, db: AsyncSession = Depends(get_db)):
    try:
        from app.utils.captcha import captcha
        is_captcha_valid = captcha.verify_captcha(user_data.captcha_id, user_data.captcha_text)

        if not is_captcha_valid:
            return JSONResponse(
                status_code=400,
                content={"detail": "Неверный код с картинки. Пожалуйста, попробуйте еще раз."}
            )

        user_service = UserService(db)
        refresh_token = request.cookies.get("refresh_token")

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
        await AuditService(db).log(request=request, event_type="error.app_exception", metadata={"route": "users.reset_password", "error": str(e)})
        return JSONResponse(
            status_code=500,
            content={"detail": f"Ошибка при сбросе пароля: {str(e)}"}
        )