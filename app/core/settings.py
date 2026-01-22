import os
from typing import Optional
from dataclasses import dataclass
from fastapi_mail import ConnectionConfig
from dotenv import load_dotenv

load_dotenv()

def _get_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    val = os.getenv(name)
    try:
        return int(val) if val is not None else default
    except (TypeError, ValueError):
        return default


@dataclass
class Settings:
    SECRET_KEY: str = os.getenv("SECRET_KEY", "change_me")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = _get_int("ACCESS_TOKEN_EXPIRE_MINUTES", 30)
    REFRESH_TOKEN_EXPIRE_DAYS: int = _get_int("REFRESH_TOKEN_EXPIRE_DAYS", 7)
    ENCRYPTION_KEY: Optional[str] = os.getenv("ENCRYPTION_KEY")
    HMAC_KEY: Optional[str] = os.getenv("HMAC_KEY")

    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    PIPELINE_VERSION: str = os.getenv("PIPELINE_VERSION", "v1")

    MAX_CONCURRENT_ANALYSES: int = _get_int("MAX_CONCURRENT_ANALYSES", 1)

    MAX_UPLOAD_BYTES: int = _get_int("MAX_UPLOAD_BYTES", 50 * 1024 * 1024)

    VT_API_KEY: Optional[str] = os.getenv("VT_API_KEY")
    YANDEX_SB_API_KEY: Optional[str] = os.getenv("YANDEX_SB_API_KEY")

    URL_META_TIMEOUT_SECONDS: int = _get_int("URL_META_TIMEOUT_SECONDS", 10)
    URL_DOWNLOAD_TIMEOUT_SECONDS: int = _get_int("URL_DOWNLOAD_TIMEOUT_SECONDS", 30)
    URL_MAX_DOWNLOAD_BYTES: int = _get_int("URL_MAX_DOWNLOAD_BYTES", 50 * 1024 * 1024)
    URL_MAX_REDIRECTS: int = _get_int("URL_MAX_REDIRECTS", 5)

    URL_RATE_LIMIT_PER_MINUTE: int = _get_int("URL_RATE_LIMIT_PER_MINUTE", 1)

    DATABASE_URL: str = os.getenv("DATABASE_URL")

    MAIL_USERNAME: Optional[str] = os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD: Optional[str] = os.getenv("MAIL_PASSWORD")
    MAIL_FROM: Optional[str] = os.getenv("MAIL_FROM")
    MAIL_PORT: int = _get_int("MAIL_PORT", 587)
    MAIL_SERVER: Optional[str] = os.getenv("MAIL_SERVER")
    MAIL_STARTTLS: bool = _get_bool("MAIL_STARTTLS", True)
    MAIL_SSL_TLS: bool = _get_bool("MAIL_SSL_TLS", False)
    MAIL_FROM_NAME: Optional[str] = os.getenv("MAIL_FROM_NAME")

    @property
    def SMTP(self) -> ConnectionConfig:
        return ConnectionConfig(
            MAIL_USERNAME=self.MAIL_USERNAME,
            MAIL_PASSWORD=self.MAIL_PASSWORD,
            MAIL_FROM=self.MAIL_FROM,
            MAIL_PORT=self.MAIL_PORT,
            MAIL_SERVER=self.MAIL_SERVER,
            MAIL_STARTTLS=self.MAIL_STARTTLS,
            MAIL_SSL_TLS=self.MAIL_SSL_TLS,
            MAIL_FROM_NAME=self.MAIL_FROM_NAME,
        )


settings = Settings()
