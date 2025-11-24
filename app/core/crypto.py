import base64
import hashlib
import hmac
from typing import Optional
from cryptography.fernet import Fernet
from app.core.settings import settings


def _get_fernet() -> Fernet:
    key = settings.ENCRYPTION_KEY
    if not key:
        digest = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
        key = base64.urlsafe_b64encode(digest)
    if isinstance(key, str):
        key_bytes = key.encode("utf-8")
    else:
        key_bytes = key
    return Fernet(key_bytes)


_fernet = _get_fernet()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def encrypt_str(value: str) -> str:
    return _fernet.encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_str(ciphertext: str) -> str:
    return _fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")


def hmac_hash(value: str) -> str:
    key = settings.HMAC_KEY or settings.SECRET_KEY
    if isinstance(key, str):
        key_bytes = key.encode("utf-8")
    else:
        key_bytes = key
    return hmac.new(key_bytes, value.encode("utf-8"), hashlib.sha256).hexdigest()


def encrypt_ip(ip: Optional[str]) -> Optional[str]:
    if not ip:
        return None
    return encrypt_str(ip)
