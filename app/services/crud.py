from sqlalchemy.future import select
from app.domain.models.user import Users
from sqlalchemy.ext.asyncio import AsyncSession

async def get_user(db: AsyncSession, user_id: int):
    result = await db.execute(select(Users).filter(Users.id == user_id))
    return result.scalars().first()

async def create_user(db: AsyncSession, username: str, email: str, hashed_password: str):
    db_user = Users(username=username, email=email, hashed_password=hashed_password)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user

