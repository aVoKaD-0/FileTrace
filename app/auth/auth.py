import ssl       
import certifi   
import string
from random import choices
from jose import JWTError, jwt
from app.config.auth import SMTP
from captcha.image import ImageCaptcha
from passlib.context import CryptContext
from fastapi_mail import FastMail, MessageSchema
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status
from datetime import datetime, timedelta, timezone
from app.config.auth import SECRET_KEY, ALGORITHM, REFRESH_TOKEN_EXPIRE_DAYS, ACCESS_TOKEN_EXPIRE_MINUTES


# Контекст для хеширования паролей с использованием bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Схема OAuth2 для получения токена из запроса
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_refresh_token(data: dict):
    # Создает JWT refresh token для долгосрочной аутентификации
    # Параметры:
    #   data: Словарь с данными пользователя (обычно содержит "sub" с ID пользователя)
    # Возвращает:
    #   Строка JWT токена
    to_encode = data.copy()
    # Устанавливаем срок действия (обычно несколько дней)
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    # Кодируем данные в токен
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_access_token(data: dict):
    # Создает JWT access token для краткосрочной аутентификации
    # Параметры:
    #   data: Словарь с данными пользователя (обычно содержит "sub" с ID пользователя)
    # Возвращает:
    #   Строка JWT токена
    to_encode = data.copy()
    # Устанавливаем срок действия (обычно несколько минут)
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    # Кодируем данные в токен
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def uuid_by_token(token: str):
    # Извлекает UUID пользователя из JWT токена
    # Параметры:
    #   token: JWT токен для декодирования
    # Возвращает:
    #   UUID пользователя из поля "sub"
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    uuid = payload.get("sub")
    return uuid

def generate_code():
    # Генерирует случайный 6-значный код для подтверждения email
    # Возвращает:
    #   Строка из 6 случайных цифр
    return ''.join(choices(string.digits, k=6))

def generate_captcha():
    # Создает изображение с CAPTCHA и возвращает текст
    # Возвращает:
    #   Словарь с полем "captcha", содержащим текст CAPTCHA
    captcha = ImageCaptcha()
    # Генерируем случайный текст из букв и цифр
    text = ''.join(choices(string.ascii_letters + string.digits, k=6))
    # Создаем изображение с CAPTCHA
    captcha.write(text, "captcha.png")
    return {"captcha": text}

async def verify_token(token: str = Depends(oauth2_scheme)):
    # Проверяет JWT токен и возвращает имя пользователя
    # Параметры:
    #   token: JWT токен для проверки (получается из запроса)
    # Возвращает:
    #   Имя пользователя из токена
    # Вызывает:
    #   HTTPException если токен недействителен
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Декодируем токен и извлекаем данные
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        # В случае ошибки декодирования, вызываем исключение
        raise credentials_exception
    return username

def refresh_token(token: str = Depends(oauth2_scheme)):
    # Обновляет токен и возвращает UUID пользователя
    # Параметры:
    #   token: JWT токен для обновления (получается из запроса)
    # Возвращает:
    #   UUID пользователя из токена
    payload = jwt.decode(token=token, key=SECRET_KEY, algorithms=[ALGORITHM])
    uuid = payload.get("sub")
    return uuid

async def send_email(email: str, verification_code: str):
    try:
        # Отправляет электронное письмо пользователю
        # Параметры:
        #   email: Адрес получателя
        #   body: Текст сообщения
        # Возвращает:
        #   None
        html_body = f"""
        <html>
            <body>
                <p>Здравствуйте!</p>
                <p>Ваш код для подтверждения регистрации <strong>{verification_code}</strong></p> 
                <p>Если вы не регистрировались, проигнорируйте это письмо.</p> 
            </body>
        </html>
        """
        # print("semd_email", email, html_body)
        message = MessageSchema(
            subject="Confirm your account",
            recipients=[email],
            body=html_body,
            subtype="html"
        )

        # ssl_context = ssl.create_default_context(cafile=certifi.where())
        # Инициализируем FastMail с настройками SMTP
        print("send_email", SMTP)
        fm = FastMail(SMTP)

        # print("send_email", message)
        # Отправляем сообщение
        await fm.send_message(message)
        print("send_email success")
    except Exception as e:
        print("send_email error", e)