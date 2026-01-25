import uuid
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from app.auth.auth import generate_code
from app.models.user import Users
from app.core.crypto import normalize_email, encrypt_str, hmac_hash
from app.utils.sse_operations import subscribers
from app.core.security import get_password_hash, verify_password
from app.utils.analysis_log_filter import sanitize_multiline

from app.repositories.analysis_repository import AnalysisRepository
from app.repositories.analysis_subscriber_repository import AnalysisSubscriberRepository
from app.repositories.result_repository import ResultRepository
from app.repositories.user_repository import UserRepository

class UserService:
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.users_repo = UserRepository(db)
        self.analysis_repo = AnalysisRepository(db)
        self.results_repo = ResultRepository(db)
        self.subscribers_repo = AnalysisSubscriberRepository(db)

    async def add(self, model) -> None:
        self.db.add(model)

    async def commit(self) -> None:
        await self.db.commit()

    async def refresh(self, model) -> None:
        await self.db.refresh(model)

    async def __add__(self, model) -> None:
        await self.add(model)

    async def __commit__(self) -> None:
        await self.commit()

    async def __refresh__(self, model: Optional[object] = None) -> None:
        if model is None:
            return
        await self.refresh(model)

    async def get_user_by_email(self, email: str):
        return await self.get_by_email(email)
    
    async def get_user_analyses(self, user_id: str):
        return await self.analysis_repo.list_user_analyses(user_id=user_id)
    
    async def get_user_by_id(self, user_id: uuid.UUID):
        return await self.users_repo.get_by_id(user_id)
    
    async def get_refresh_token(self, refresh_token: str):
        return await self.get_by_refresh_token(refresh_token)
    
    async def get_result_data(self, analysis_id: str) -> dict:

        result_obj = await self.results_repo.get_by_analysis_id(analysis_id)
        analysis_obj = await self.results_repo.get_analysis(analysis_id)
        
        if not result_obj and not analysis_obj:
            return {
                "status": "unknown",
                "file_activity": "",
                "docker_output": "",
                "total": 0
            }
        
        return {
            "status": analysis_obj.status if analysis_obj else "unknown",
            "file_activity": result_obj.file_activity if result_obj and result_obj.file_activity else "",
            "docker_output": sanitize_multiline(result_obj.docker_output) if result_obj and result_obj.docker_output else "",
            "total": result_obj.results if result_obj and result_obj.results else 0
        }

    async def get_chunk_result(self, analysis_id: str, offset: int = 0, limit: int = 50):
        return await self.results_repo.get_chunk_result(analysis_id, offset=offset, limit=limit)

    async def create_user(self,  email: str, password: str):
        
        hashed_password = get_password_hash(password)
        confirmation_code = generate_code()
        expires_at = datetime.utcnow() + timedelta(minutes=10)
        created_at = datetime.utcnow()
        
        new_user = Users(
            email_hash=hmac_hash(normalize_email(email)),
            email_encrypted=encrypt_str(email), 
            hashed_password=hashed_password, 
            confirmation_code=confirmation_code, 
            created_at=created_at, 
            expires_at=expires_at
        )
        await self.add(new_user)
        await self.commit()
        await self.refresh(new_user)
        return new_user.id, confirmation_code
    
    async def update_password(self, email=None, password=None, refresh_token=None):
        from app.core.security import get_password_hash
        
        if refresh_token:
            user = await self.get_by_refresh_token(refresh_token)
        elif email:
            user = await self.get_by_email(email)
        else:
            return None
        
        if user is None:
            return None
        
        if password:
            user.hashed_password = get_password_hash(password)
        
        user.login_attempts = 0
        
        await self.add(user)
        await self.commit()
        
        return user

    async def get_by_refresh_token(self, refresh_token):
        return await self.users_repo.get_by_refresh_token(refresh_token)

    async def create_analysis(self, user_id: str, filename: str, status: str, analysis_id: uuid.UUID):
        await self.analysis_repo.create(user_id=user_id, filename=filename, status=status, analysis_id=analysis_id)

    async def create_hash_analysis(self, *, user_id: str, filename: str, status: str, analysis_id: uuid.UUID, file_hash: str, pipeline_version: str):
        await self.analysis_repo.create(
            user_id=user_id,
            filename=filename,
            status=status,
            analysis_id=analysis_id,
            file_hash=file_hash,
            pipeline_version=pipeline_version,
        )

    async def find_latest_completed_by_hash(self, *, file_hash: str, pipeline_version: str):
        return await self.analysis_repo.find_latest_completed_by_hash(file_hash=file_hash, pipeline_version=pipeline_version)

    async def find_active_by_hash(self, *, file_hash: str, pipeline_version: str):
        return await self.analysis_repo.find_active_by_hash(file_hash=file_hash, pipeline_version=pipeline_version)

    async def subscribe_user_to_analysis(self, *, analysis_id: uuid.UUID, user_id: uuid.UUID):
        await self.subscribers_repo.ensure_subscribed(analysis_id=analysis_id, user_id=user_id)

    async def create_result(self, analysis_id: uuid.UUID):
        await self.results_repo.create_empty(analysis_id)

    async def update_refresh_token(self, email, refresh_token):
        user = await self.users_repo.get_by_email(email)
        if not user:
            return None

        return await self.users_repo.set_refresh_token(user=user, refresh_token=refresh_token)
        
    async def notify_analysis_completed(self, analysis_id: str):
        for q in subscribers:
            await q.put({"status": "completed", "analysis_id": analysis_id})

    async def get_analysis_by_id(self, analysis_id: str):
        return await self.analysis_repo.get_by_id(analysis_id)

    async def authenticate_user(self, email: str, password: str):
        user = await self.get_user_by_email(email)
        if not user:
            return None
        
        if not verify_password(password, user.hashed_password):
            return None
        
        return user

    async def get_by_email(self, email: str):
        return await self.users_repo.get_by_email(email)

    async def update_refresh_token_by_user_id(self, user_id: uuid.UUID, refresh_token):
        user = await self.users_repo.get_by_id(user_id)
        if not user:
            return None
        return await self.users_repo.set_refresh_token(user=user, refresh_token=refresh_token)

    async def get_login_attempts(self, email: str) -> int:
        return await self.users_repo.get_login_attempts(email)

    async def increment_login_attempts(self, email: str):
        user = await self.users_repo.get_by_email(email)
        if not user:
            return

        await self.users_repo.set_login_attempts(user=user, attempts=(user.login_attempts or 0) + 1)

    async def reset_login_attempts(self, email: str):
        user = await self.users_repo.get_by_email(email)
        if not user:
            return

        await self.users_repo.set_login_attempts(user=user, attempts=0)