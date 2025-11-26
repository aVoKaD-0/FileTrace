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


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def uuid_by_token(token: str):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    uuid = payload.get("sub")
    return uuid

def generate_code():
    return ''.join(choices(string.digits, k=6))

def generate_captcha():
    captcha = ImageCaptcha()
    text = ''.join(choices(string.ascii_letters + string.digits, k=6))
    captcha.write(text, "captcha.png")
    return {"captcha": text}

async def verify_token(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username

def refresh_token(token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token=token, key=SECRET_KEY, algorithms=[ALGORITHM])
    uuid = payload.get("sub")
    return uuid

async def send_email(email: str, verification_code: str):
    try:
        html_body = f"""
        <html>
            <body>
                <p>Здравствуйте!</p>
                <p>Ваш код для подтверждения регистрации <strong>{verification_code}</strong></p> 
                <p>Если вы не регистрировались, проигнорируйте это письмо.</p> 
            </body>
        </html>
        """
        message = MessageSchema(
            subject="Confirm your account",
            recipients=[email],
            body=html_body,
            subtype="html"
        )

        fm = FastMail(SMTP)

        await fm.send_message(message)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to send email")

async def send_reset_password_email(email: str, reset_link: str):
    try:
        html_body = f"""
        <html>
            <body>
                <p>Здравствуйте!</p>
                <p>Вы запросили сброс пароля для вашей учетной записи.</p>
                <p>Перейдите по ссылке ниже, чтобы установить новый пароль:</p>
                <p><a href="{reset_link}">Сбросить пароль</a></p>
                <p>Если вы не запрашивали сброс пароля, просто проигнорируйте это письмо.</p>
            </body>
        </html>
        """

        message = MessageSchema(
            subject="Reset your password",
            recipients=[email],
            body=html_body,
            subtype="html"
        )

        fm = FastMail(SMTP)
        await fm.send_message(message)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to send email")