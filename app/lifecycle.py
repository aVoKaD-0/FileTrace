import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator, Callable

from fastapi import FastAPI

from app.services.cleanup_service import CleanupService
from app.services.etw_collector_singleton import etw_collector

def build_lifespan(cleanup_service: CleanupService) -> Callable[[FastAPI], AsyncIterator[None]]:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        etw_collector.start_process()
        await cleanup_service.start()
        try:
            yield
        finally:
            await asyncio.shield(cleanup_service.stop())
            etw_collector.stop_process()

    return lifespan
