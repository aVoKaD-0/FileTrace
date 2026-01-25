from apscheduler.triggers.interval import IntervalTrigger
from app.infra.db.session import AsyncSessionLocal
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.repositories.user_repository import UserRepository

class CleanupService:
    def __init__(self):
        self.scheduler = None

    async def start(self):
        if self.scheduler is None:
            self.scheduler = AsyncIOScheduler()
            self.scheduler.add_job(
                self.cleanup_expired_users,
                trigger=IntervalTrigger(minutes=10),
                id='cleanup_expired_users'
            )
            self.scheduler.start()

    async def cleanup_expired_users(self):
        async with AsyncSessionLocal() as db:
            await UserRepository(db).delete_unconfirmed_users()

    async def stop(self):
        if self.scheduler:
            try:
                self.scheduler.shutdown(wait=False)
            except Exception:
                pass
            self.scheduler = None