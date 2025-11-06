import asyncpg
import asyncio
from app.config.db import DATABASE_URL

class AsyncPostgresDB:
    def __init__(self, dsn):
        self.dsn = dsn
        self.pool = None

    async def connect(self):
        self.pool = await asyncpg.create_pool(self.dsn)

    async def execute(self, query, params=None, fetch=False):
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                result = await conn.fetch(query, *params) if fetch else await conn.execute(query, *params)
                return result if fetch else None

    async def close(self):
        await self.pool.close()

async def main():
    db = AsyncPostgresDB(DATABASE_URL)
    await db.connect()

    await db.execute("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(255), password VARCHAR(255))")
    users = await db.execute("SELECT * FROM users", fetch=True)

    await db.close()

asyncio.run(main())
