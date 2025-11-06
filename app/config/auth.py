from fastapi_mail import ConnectionConfig
import os

SECRET_KEY = "secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

SMTP = ConnectionConfig(
    MAIL_USERNAME = os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD"),
    MAIL_FROM = os.getenv("MAIL_FROM"),
    MAIL_PORT = os.getenv("MAIL_PORT"),
    MAIL_SERVER = os.getenv("MAIL_SERVER"),
    MAIL_STARTTLS  = os.getenv("MAIL_STARTTLS"),
    MAIL_SSL_TLS = os.getenv("MAIL_SSL_TLS"),
    MAIL_FROM_NAME = os.getenv("MAIL_FROM_NAME")
)