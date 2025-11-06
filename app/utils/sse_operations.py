import asyncio
from typing import List

subscribers: List[asyncio.Queue] = []

async def notify_subscribers(update_msg):
    for q in subscribers:
        await q.put(update_msg) 