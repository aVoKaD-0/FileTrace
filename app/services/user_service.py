from sqlite3 import Time
import uuid 
from sqlalchemy import select
from sqlalchemy.sql import text
from app.auth.auth import generate_code
from app.models.user import Users
from app.core.crypto import normalize_email, encrypt_str, decrypt_str, hmac_hash

from datetime import datetime, timedelta   
from sqlalchemy.ext.asyncio import AsyncSession
from app.utils.sse_operations import subscribers
from app.models.analysis import Analysis
from app.models.result import Results

from app.core.security import get_password_hash, verify_password

class UserService:
    # Сервис для работы с пользователями
    # Предоставляет методы для управления пользовательскими данными,
    # аутентификации, восстановления пароля и анализов
    
    def __init__(self, db: AsyncSession):
        # Инициализация сервиса пользователей
        # Параметры:
        #   db: Асинхронная сессия базы данных
        self.db = db

    async def __refresh__(self, model):
        # Обновляет данные модели из базы данных
        # Параметры:
        #   model: Объект модели для обновления
        await self.db.refresh(model)

    async def get_user_by_email(self, email: str):
        # Получает пользователя по email (алиас для метода get_by_email)
        # Параметры:
        #   email: Email пользователя
        # Возвращает:
        #   Объект пользователя или None
        return await self.get_by_email(email)
    
    async def get_user_analyses(self, user_id: str):
        # Получает список анализов пользователя
        # Параметры:
        #   user_id: ID пользователя
        # Возвращает:
        #   Список анализов пользователя
        result = await self.db.execute(
            select(Analysis.timestamp, Analysis.filename, Analysis.status, Analysis.analysis_id)
            .filter(Analysis.user_id == user_id)
        )
        return result.all()
    
    async def get_user_by_id(self, user_id: uuid.UUID):
        # Получает пользователя по его ID
        # Параметры:
        #   user_id: UUID пользователя
        # Возвращает:
        #   Объект пользователя или None
        result = await self.db.execute(select(Users).filter(Users.id == user_id))
        return result.scalars().first()
    
    async def get_refresh_token(self, refresh_token: str):
        # Получает пользователя по refresh token (алиас для get_by_refresh_token)
        # Параметры:
        #   refresh_token: Токен обновления
        # Возвращает:
        #   Объект пользователя или None
        return await self.get_by_refresh_token(refresh_token)
    
    async def get_result_data(self, analysis_id: str) -> dict:
        # Получает результаты анализа по его ID
        # Параметры:
        #   analysis_id: ID анализа
        # Возвращает:
        #   Словарь с данными результатов анализа
        result = await self.db.execute(
            select(Results).filter(Results.analysis_id == analysis_id)
        )
        result_obj = result.scalars().first()
        
        analysis = await self.db.execute(
            select(Analysis).filter(Analysis.analysis_id == analysis_id)
        )
        analysis_obj = analysis.scalars().first()
        
        # Если анализ или результаты не найдены, возвращаем пустые данные
        if not result_obj and not analysis_obj:
            return {
                "status": "unknown",
                "file_activity": "",
                "docker_output": "",
                "total": 0
            }
        
        # Возвращаем данные анализа и результаты
        return {
            "status": analysis_obj.status if analysis_obj else "unknown",
            "file_activity": result_obj.file_activity if result_obj and result_obj.file_activity else "",
            "docker_output": result_obj.docker_output if result_obj and result_obj.docker_output else "",
            "total": result_obj.results if result_obj and result_obj.results else 0
        }

    async def get_chunk_result(self, analysis_id: str, offset: int = 0, limit: int = 50):
        # Получает часть результатов анализа с пагинацией
        # Параметры:
        #   analysis_id: ID анализа
        #   offset: Смещение (начальная позиция)
        #   limit: Лимит (количество записей)
        # Возвращает:
        #   Кортеж (результаты, общее количество)
        
        # Получаем ограниченную часть результатов с помощью JSON-функций PostgreSQL
        result = await self.db.execute(
            text(f"""
                SELECT jsonb_path_query_array(
                    file_activity,
                    '$.items[{offset} to {offset + limit - 1}]'
                )
                FROM results
                WHERE analysis_id = :analysis_id
            """),
            {"analysis_id": analysis_id}
        )
        
        # Получаем общее количество записей
        total = await self.db.execute(
            text("""SELECT jsonb_array_length(file_activity) FROM results WHERE analysis_id = :analysis_id"""),
            {"analysis_id": analysis_id}
        )
        return result.scalars().all(), total.scalars().first()

    async def create_user(self,  email: str, password: str):
        # Создает нового пользователя
        # Параметры:
        #   email: Email пользователя
        #   password: Пароль пользователя (будет хэширован)
        # Возвращает:
        #   Кортеж (ID пользователя, код подтверждения)
        
        # Хэшируем пароль для безопасного хранения
        hashed_password = get_password_hash(password)
        # Генерируем код подтверждения
        confirmation_code = generate_code()
        # Устанавливаем срок действия кода (10 минут)
        expires_at = datetime.utcnow() + timedelta(minutes=10)
        created_at = datetime.utcnow()
        
        # Создаем нового пользователя
        new_user = Users(
            email_hash=hmac_hash(normalize_email(email)),
            email_encrypted=encrypt_str(email), 
            hashed_password=hashed_password, 
            confirmation_code=confirmation_code, 
            created_at=created_at, 
            expires_at=expires_at
        )
        self.db.add(new_user)
        await self.db.commit()
        await self.db.refresh(new_user)
        return new_user.id, confirmation_code
    
    async def update_password(self, email=None, password=None, refresh_token=None):
        # Обновляет пароль пользователя
        # Параметры:
        #   email: Email пользователя (опционально)
        #   password: Новый пароль (опционально)
        #   refresh_token: Refresh token для идентификации (опционально)
        # Возвращает:
        #   Объект пользователя или None
        from app.core.security import get_password_hash
        
        # Если передан refresh_token, получаем пользователя по нему
        if refresh_token:
            user = await self.get_by_refresh_token(refresh_token)
        # Иначе, если передан email, получаем пользователя по email
        elif email:
            user = await self.get_by_email(email)
        else:
            return None
        
        if user is None:
            return None
        
        # Обновляем пароль, если передан новый
        if password:
            user.hashed_password = get_password_hash(password)
        
        # Сбрасываем счетчик попыток входа при смене пароля
        user.login_attempts = 0
        
        # Сохраняем изменения
        self.db.add(user)
        await self.db.commit()
        
        return user

    async def get_by_refresh_token(self, refresh_token):
        # Получает пользователя по refresh token
        # Параметры:
        #   refresh_token: Токен обновления
        # Возвращает:
        #   Объект пользователя или None
        query = select(Users).where(Users.refresh_token == refresh_token)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def __add__(self, model):
        # Добавляет модель в сессию БД
        # Параметры:
        #   model: Объект модели для добавления
        self.db.add(model)
    
    async def __commit__(self):
        # Фиксирует изменения в БД
        await self.db.commit()

    async def __refresh__(self):
        # Обновляет данные модели из БД
        await self.db.refresh()

    async def create_analysis(self, user_id: str, filename: str, status: str, analysis_id: uuid.UUID):
        # Создает новую запись анализа
        # Параметры:
        #   user_id: ID пользователя
        #   filename: Имя анализируемого файла
        #   timestamp: Временная метка
        #   status: Статус анализа
        #   analysis_id: UUID анализа
        analysis = Analysis(
            user_id=user_id, 
            filename=filename,  
            status=status, 
            analysis_id=analysis_id
        )
        self.db.add(analysis)
        await self.db.commit()
    
    async def create_result(self, analysis_id: uuid.UUID):
        # Создает пустую запись результатов для анализа
        # Параметры:
        #   analysis_id: UUID анализа
        result = Results(
            analysis_id=analysis_id, 
            file_activity="", 
            docker_output="", 
            results=""
        )
        self.db.add(result)
        await self.db.commit()

    async def update_refresh_token(self, email, refresh_token):
        # Обновляет refresh token пользователя
        # Параметры:
        #   email: Email пользователя
        #   refresh_token: Новый refresh token или None для сброса
        # Возвращает:
        #   Объект пользователя или None
        user = await self.get_by_email(email)
        if not user:
            return None
        
        user.refresh_token = refresh_token
        self.db.add(user)
        await self.db.commit()
        return user
        
    async def notify_analysis_completed(self, analysis_id: str):
        # Уведомляет подписчиков о завершении анализа через SSE
        # Параметры:
        #   analysis_id: ID завершенного анализа
        for q in subscribers:
            await q.put({"status": "completed", "analysis_id": analysis_id})

    async def get_analysis_by_id(self, analysis_id: str):
        # Получает анализ по его ID
        # Параметры:
        #   analysis_id: ID анализа
        # Возвращает:
        #   Объект анализа или None
        query = select(Analysis).filter(Analysis.analysis_id == analysis_id)
        result = await self.db.execute(query)
        return result.scalars().first()

    async def authenticate_user(self, email: str, password: str):
        # Аутентифицирует пользователя по email и паролю
        # Параметры:
        #   email: Email пользователя
        #   password: Пароль пользователя
        # Возвращает:
        #   Объект пользователя если аутентификация успешна, None в противном случае
        user = await self.get_user_by_email(email)
        if not user:
            return None
        
        # Проверяем пароль
        if not verify_password(password, user.hashed_password):
            return None
        
        return user

    async def get_by_email(self, email: str):
        # Получает пользователя по email (поиск по детерминированному хэшу)
        email_norm = normalize_email(email)
        email_hash = hmac_hash(email_norm)
        query = select(Users).where(Users.email_hash == email_hash)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def update_refresh_token_by_user_id(self, user_id: uuid.UUID, refresh_token):
        # Обновляет refresh token по user_id
        result = await self.db.execute(select(Users).filter(Users.id == user_id))
        user = result.scalars().first()
        if not user:
            return None
        user.refresh_token = refresh_token
        self.db.add(user)
        await self.db.commit()
        return user

    async def get_login_attempts(self, email: str) -> int:
        # Получает количество неудачных попыток входа для пользователя
        # Параметры:
        #   email: Email пользователя
        # Возвращает:
        #   Количество неудачных попыток входа
        user = await self.get_by_email(email)
        if not user:
            return 0
        
        return user.login_attempts or 0

    async def increment_login_attempts(self, email: str):
        # Увеличивает счетчик неудачных попыток входа
        # Параметры:
        #   email: Email пользователя
        user = await self.get_by_email(email)
        if not user:
            return
        
        # Увеличиваем счетчик на 1
        user.login_attempts = (user.login_attempts or 0) + 1
        
        # Сохраняем изменения
        self.db.add(user)
        await self.db.commit()

    async def reset_login_attempts(self, email: str):
        # Сбрасывает счетчик неудачных попыток входа
        # Параметры:
        #   email: Email пользователя
        user = await self.get_by_email(email)
        if not user:
            return
        
        # Сбрасываем счетчик
        user.login_attempts = 0
        
        # Сохраняем изменения
        self.db.add(user)
        await self.db.commit()