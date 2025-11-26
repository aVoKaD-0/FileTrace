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
    
    def __init__(self, db: AsyncSession):
        self.db = db

    async def __refresh__(self, model):
        await self.db.refresh(model)

    async def get_user_by_email(self, email: str):
        return await self.get_by_email(email)
    
    async def get_user_analyses(self, user_id: str):
        result = await self.db.execute(
            select(Analysis.timestamp, Analysis.filename, Analysis.status, Analysis.analysis_id)
            .filter(Analysis.user_id == user_id)
        )
        return result.all()
    
    async def get_user_by_id(self, user_id: uuid.UUID):
        result = await self.db.execute(select(Users).filter(Users.id == user_id))
        return result.scalars().first()
    
    async def get_refresh_token(self, refresh_token: str):
        return await self.get_by_refresh_token(refresh_token)
    
    async def get_result_data(self, analysis_id: str) -> dict:
        result = await self.db.execute(
            select(Results).filter(Results.analysis_id == analysis_id)
        )
        result_obj = result.scalars().first()
        
        analysis = await self.db.execute(
            select(Analysis).filter(Analysis.analysis_id == analysis_id)
        )
        analysis_obj = analysis.scalars().first()
        
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
            "docker_output": result_obj.docker_output if result_obj and result_obj.docker_output else "",
            "total": result_obj.results if result_obj and result_obj.results else 0
        }

    async def get_chunk_result(self, analysis_id: str, offset: int = 0, limit: int = 50):
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
        
        total = await self.db.execute(
            text("""SELECT jsonb_array_length(file_activity) FROM results WHERE analysis_id = :analysis_id"""),
            {"analysis_id": analysis_id}
        )
        return result.scalars().all(), total.scalars().first()

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
        self.db.add(new_user)
        await self.db.commit()
        await self.db.refresh(new_user)
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
        
        self.db.add(user)
        await self.db.commit()
        
        return user

    async def get_by_refresh_token(self, refresh_token):
        query = select(Users).where(Users.refresh_token == refresh_token)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def __add__(self, model):
        self.db.add(model)
    
    async def __commit__(self):
        await self.db.commit()

    async def __refresh__(self):
        await self.db.refresh()

    async def create_analysis(self, user_id: str, filename: str, status: str, analysis_id: uuid.UUID):
        analysis = Analysis(
            user_id=user_id, 
            filename=filename,  
            status=status, 
            analysis_id=analysis_id
        )
        self.db.add(analysis)
        await self.db.commit()
    
    async def create_result(self, analysis_id: uuid.UUID):
        result = Results(
            analysis_id=analysis_id, 
            file_activity="", 
            docker_output="", 
            results=""
        )
        self.db.add(result)
        await self.db.commit()

    async def update_refresh_token(self, email, refresh_token):
        user = await self.get_by_email(email)
        if not user:
            return None
        
        user.refresh_token = refresh_token
        self.db.add(user)
        await self.db.commit()
        return user
        
    async def notify_analysis_completed(self, analysis_id: str):
        for q in subscribers:
            await q.put({"status": "completed", "analysis_id": analysis_id})

    async def get_analysis_by_id(self, analysis_id: str):
        query = select(Analysis).filter(Analysis.analysis_id == analysis_id)
        result = await self.db.execute(query)
        return result.scalars().first()

    async def authenticate_user(self, email: str, password: str):
        user = await self.get_user_by_email(email)
        if not user:
            return None
        
        if not verify_password(password, user.hashed_password):
            return None
        
        return user

    async def get_by_email(self, email: str):
        email_norm = normalize_email(email)
        email_hash = hmac_hash(email_norm)
        query = select(Users).where(Users.email_hash == email_hash)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def update_refresh_token_by_user_id(self, user_id: uuid.UUID, refresh_token):
        result = await self.db.execute(select(Users).filter(Users.id == user_id))
        user = result.scalars().first()
        if not user:
            return None
        user.refresh_token = refresh_token
        self.db.add(user)
        await self.db.commit()
        return user

    async def get_login_attempts(self, email: str) -> int:
        user = await self.get_by_email(email)
        if not user:
            return 0
        
        return user.login_attempts or 0

    async def increment_login_attempts(self, email: str):
        user = await self.get_by_email(email)
        if not user:
            return
        
        user.login_attempts = (user.login_attempts or 0) + 1
        
        self.db.add(user)
        await self.db.commit()

    async def reset_login_attempts(self, email: str):
        user = await self.get_by_email(email)
        if not user:
            return
        
        user.login_attempts = 0
        
        self.db.add(user)
        await self.db.commit()