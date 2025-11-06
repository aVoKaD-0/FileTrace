from typing import Optional
from pydantic import EmailStr
from pydantic import BaseModel

class SingUpRequest(BaseModel):
    # Схема для регистрации пользователя (запрос)
    # Используется для получения данных при создании нового аккаунта
    email: str  # Email пользователя для регистрации
    password: str  # Пароль пользователя (в открытом виде)

class SingUpResponse(BaseModel):
    # Схема ответа на успешную регистрацию
    # Возвращает идентификатор пользователя и токен доступа
    id: int  # Идентификатор созданного пользователя
    token: str  # JWT токен для авторизации

class SignInRequest(BaseModel):
    # Схема для входа пользователя (запрос)
    # Используется для получения учетных данных при входе
    email: str  # Email пользователя для входа
    password: str  # Пароль пользователя (в открытом виде)

class SignInResponse(BaseModel):
    # Схема ответа на успешный вход
    # Возвращает идентификатор пользователя и токен доступа
    id: int  # Идентификатор пользователя
    token: str  # JWT токен для авторизации

class UserUpdateRequest(BaseModel):
    # Схема для обновления данных пользователя
    # Используется для изменения профиля пользователя
    username: str  # Имя пользователя
    email: EmailStr  # Email пользователя (с валидацией)
    password: str  # Новый пароль пользователя

class UserUpdateResponse(BaseModel):
    # Схема ответа на успешное обновление пользователя
    # Возвращает идентификатор и новый токен (если учетные данные изменились)
    id: int  # Идентификатор пользователя
    token: str  # Новый JWT токен

class UserDeleteRequest(BaseModel):
    # Схема для удаления пользователя
    # Используется для получения данных при удалении аккаунта
    id: int  # Идентификатор пользователя для удаления
    token: str  # Токен для подтверждения операции

class UserDeleteResponse(BaseModel):
    # Схема ответа на успешное удаление пользователя
    # Возвращает статус операции
    status: bool  # Флаг успешного удаления (True/False)

class EmailConfirmation(BaseModel):
    # Схема для подтверждения электронной почты
    # Используется для верификации адреса пользователя
    code: str  # Код подтверждения из письма

class ResetPasswordRequest(BaseModel):
    # Схема для сброса пароля (устаревшая)
    # Используется для сброса пароля пользователя
    password: str  # Новый пароль
    email: str = None  # Email пользователя (опционально)
    old_password: str = None  # Старый пароль (опционально)

class ResetPasswordResponse(BaseModel):
    # Схема ответа на успешный сброс пароля
    # Возвращает статус операции
    status: bool  # Флаг успешного сброса (True/False)

class UserLogin(BaseModel):
    # Схема для входа пользователя с поддержкой CAPTCHA
    # CAPTCHA становится обязательной после нескольких неудачных попыток входа
    email: str  # Email пользователя для входа
    password: str  # Пароль пользователя (в открытом виде)
    captcha_id: Optional[str] = None  # ID изображения CAPTCHA (если требуется)
    captcha_text: Optional[str] = None  # Текст, введенный пользователем с CAPTCHA

class UserRegistration(BaseModel):
    # Схема для регистрации пользователя с CAPTCHA
    # CAPTCHA обязательна при регистрации для защиты от ботов
    email: str  # Email пользователя для регистрации
    password: str  # Пароль пользователя (в открытом виде)
    captcha_id: str  # ID изображения CAPTCHA
    captcha_text: str  # Текст, введенный пользователем с CAPTCHA

class UserPasswordReset(BaseModel):
    # Схема для сброса пароля с защитой CAPTCHA
    # Используется для безопасного сброса пароля
    password: str  # Новый пароль
    captcha_id: str  # ID изображения CAPTCHA
    captcha_text: str  # Текст, введенный пользователем с CAPTCHA
    email: Optional[str] = None  # Email пользователя (опционально, если пользователь авторизован)
    old_password: Optional[str] = None  # Старый пароль (требуется если пользователь не авторизован)