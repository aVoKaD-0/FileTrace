from fastapi import Response
from fastapi.staticfiles import StaticFiles
from app.core.security import verify_password
from app.domain.models.database import get_db
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.security import OAuth2PasswordBearer
from app.services.user_service import UserService
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from app.auth.auth import send_email, create_access_token, create_refresh_token, generate_code
from app.schemas.users import EmailConfirmation, UserLogin, UserRegistration, UserPasswordReset


# Создаем маршрутизатор для пользовательских операций
router = APIRouter(prefix="/users", tags=["users"])

# Подключаем статические файлы и шаблоны
router.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

@router.get("/", response_class=HTMLResponse)
async def root(request: Request):
    # Главная страница пользовательского интерфейса
    # Возвращает HTML-страницу с формами входа и регистрации
    return templates.TemplateResponse("user.html", {"request": request})

@router.post("/registration")
async def register_user(response: Response, user_data: UserRegistration, db: AsyncSession = Depends(get_db)):
    # Обработчик регистрации нового пользователя
    # Принимает данные пользователя, проверяет капчу и создает новую учетную запись
    try:
        # Проверяем капчу для защиты от автоматической регистрации
        print(1, user_data.captcha_id, user_data.captcha_text)
        from app.utils.captcha import captcha
        is_captcha_valid = captcha.verify_captcha(user_data.captcha_id, user_data.captcha_text)

        print(2, is_captcha_valid)
        
        if not is_captcha_valid:
            return JSONResponse(
                status_code=400,
                content={"detail": "Неверный код с картинки. Пожалуйста, попробуйте еще раз."}
            )
        
        print(3, is_captcha_valid)
        
        response.set_cookie(key="email", value=user_data.email, max_age=60 * 10*60)
        
        user_service = UserService(db)
        print(4, user_service)
        
        # Проверяем, существует ли пользователь с таким email
        existing_user = await user_service.get_by_email(user_data.email)
        print(5, existing_user)
        if existing_user:
            return JSONResponse(
                status_code=400,
                content={"detail": "Пользователь с таким email уже существует"}
            )
        
        # Создаем нового пользователя
        confirm_code = await user_service.create_user(user_data.email, user_data.password)
        print(6, confirm_code)
        # Отправляем email с токеном для подтверждения
        await send_email(email=user_data.email, verification_code=f"{confirm_code}")
        print(7, confirm_code)
        return {"message": "Пользователь успешно зарегистрирован"}
    except Exception as e:
        # Обработка ошибок при регистрации
        print(8, e)
        return JSONResponse(
            status_code=500,
            content={"detail": f"Ошибка при регистрации: {str(e)}"}
        )

@router.get("/confirm-email", response_class=HTMLResponse)
def confirm_email_page(request: Request):
    # Страница подтверждения email
    # Проверяет куки и отображает форму для ввода кода подтверждения
    if not request.cookies.get("email") or request.cookies.get("refresh_token") or request.cookies.get("access_token"):
        return RedirectResponse(url="/users/")
    return templates.TemplateResponse("confirm_email.html", {"request": request})

@router.post("/confirm")
async def confirm_email(request: Request, response: Response, EmailConfirmation: EmailConfirmation, db: AsyncSession = Depends(get_db)):
    # Обработчик подтверждения email
    # Проверяет код подтверждения и активирует аккаунт
    userservice = UserService(db)
    email = request.cookies.get("email")
    user = await userservice.get_user_by_email(email)
    if user and EmailConfirmation.code == user.confirmation_code:
        # Код верный, подтверждаем пользователя
        user.confirmed = True
        user.confirmation_code = None
        
        # Создаем токены авторизации
        access_token = create_access_token({"sub": str(user.id)})
        refresh_token = create_refresh_token({"sub": str(user.id)})
        
        # Сохраняем refresh токен и устанавливаем куки
        await userservice.update_refresh_token(email, refresh_token)
        response.set_cookie(key="access_token", value=access_token, httponly=True, max_age=30*60)
        response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, max_age=7*24*60*60)
        await userservice.__commit__()
        return {"message": "Email confirmed"}
    
    # Неверный код подтверждения
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
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Неверный код с картинки. Пожалуйста, попробуйте еще раз."}
                )
        else:
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
                return JSONResponse(
                    status_code=400,
                    content={
                        "detail": "Неверный email или пароль",
                        "require_captcha": True
                    }
                )
            
            # Обычная ошибка авторизации
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
        await user_service.update_refresh_token(user.email, refresh_token)
        
        # Устанавливаем cookie с токенами
        response.set_cookie(key="access_token", value=access_token, httponly=True, max_age=30*60)
        response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, max_age=7*24*60*60)
        
        return {"message": "Вход выполнен успешно"}
    except Exception as e:
        # Обработка ошибок при входе
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
        await user_service.update_refresh_token(user.email, None)
        
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
    email = request.cookies.get("email")
    if not email:
        return RedirectResponse(url="/users/")
        
    userservice = UserService(db)
    user = await userservice.get_user_by_email(email)
    
    # Генерируем новый код
    confirmation_code = generate_code()
    user.confirmation_code = confirmation_code
    await userservice.__commit__()
    
    # Отправляем код на email
    await send_email(email, f"Confirmation code: {confirmation_code}")
    return JSONResponse(content={"message": "Email sent"})

@router.get("/reset-password", response_class=HTMLResponse)
async def reset_password(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    # Страница сброса пароля
    # Проверяет наличие refresh токена и определяет тип формы для отображения
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        userservice = UserService(db)
        user = await userservice.get_refresh_token(refresh_token=refresh_token)
        if user is None:
            # Если токен недействителен, удаляем его
            response.cookies.delete("refresh_token")
            return RedirectResponse(url="/users/")
            
    # Определяем, авторизован ли пользователь
    has_token = refresh_token is not None
    return templates.TemplateResponse(
        "reset_password.html", 
        {"request": request, "has_token": has_token}
    )

@router.post("/reset-password")
async def reset_password(request: Request, user_data: UserPasswordReset, db: AsyncSession = Depends(get_db)):
    # Обработчик сброса пароля
    # Проверяет капчу, старый пароль (если требуется) и обновляет пароль пользователя
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
        
        if refresh_token:
            # Пользователь авторизован, используем его токен для сброса
            user = await user_service.update_password(refresh_token=refresh_token, password=user_data.password)
            if user is None:
                # Если токен недействителен, пробуем использовать email
                if user_data.email:
                    await user_service.update_password(user_data.email, user_data.password)
                    return {"message": "Пароль успешно обновлен"}
                else:
                    return JSONResponse(
                        status_code=404, 
                        content={"detail": "Пользователь не найден"}
                    )
        else:
            # Пользователь не авторизован, используем email и старый пароль
            if not user_data.email:
                return JSONResponse(
                    status_code=400, 
                    content={"detail": "Email обязателен, если вы не авторизованы"}
                )
                
            user = await user_service.get_by_email(user_data.email)
            if user is None:
                return JSONResponse(
                    status_code=404, 
                    content={"detail": "Пользователь не найден"}
                )
                
            if not user_data.old_password:
                return JSONResponse(
                    status_code=400, 
                    content={"detail": "Старый пароль обязателен, если вы не авторизованы"}
                )
                
            if not verify_password(user_data.old_password, user.hashed_password):
                return JSONResponse(
                    status_code=400, 
                    content={"detail": "Неверный старый пароль"}
                )
                
            await user_service.update_password(user_data.email, user_data.password)
            
        return {"message": "Пароль успешно обновлен"}
    except Exception as e:
        # Обработка ошибок при сбросе пароля
        import logging
        logging.error(f"Ошибка при сбросе пароля: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"detail": f"Ошибка при сбросе пароля: {str(e)}"}
        )