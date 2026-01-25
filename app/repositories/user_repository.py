import uuid
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import hmac_hash, normalize_email
from app.models.user import Users


class UserRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, user_id) -> Optional[Users]:
        user_uuid = user_id
        if not isinstance(user_id, uuid.UUID):
            try:
                user_uuid = uuid.UUID(str(user_id))
            except Exception:
                return None

        result = await self.db.execute(select(Users).where(Users.id == user_uuid))
        return result.scalars().first()

    async def get_by_email(self, email: str) -> Optional[Users]:
        email_norm = normalize_email(email)
        email_hash = hmac_hash(email_norm)
        result = await self.db.execute(select(Users).where(Users.email_hash == email_hash))
        return result.scalar_one_or_none()

    async def get_by_refresh_token(self, refresh_token: str) -> Optional[Users]:
        result = await self.db.execute(select(Users).where(Users.refresh_token == refresh_token))
        return result.scalar_one_or_none()

    async def get_login_attempts(self, email: str) -> int:
        user = await self.get_by_email(email)
        if not user:
            return 0
        return user.login_attempts or 0

    async def set_login_attempts(self, *, user: Users, attempts: int) -> Users:
        user.login_attempts = attempts
        self.db.add(user)
        await self.db.commit()
        return user

    async def set_refresh_token(self, *, user: Users, refresh_token: str) -> Users:
        user.refresh_token = refresh_token
        self.db.add(user)
        await self.db.commit()
        return user

    async def list_unconfirmed_users(self):
        result = await self.db.execute(select(Users).where(Users.confirmed == False))
        return result.scalars().all()

    async def delete_users(self, users) -> None:
        for user in users:
            await self.db.delete(user)
        await self.db.commit()

    async def delete_unconfirmed_users(self) -> int:
        users = await self.list_unconfirmed_users()
        if not users:
            return 0
        await self.delete_users(users)
        return len(users)
