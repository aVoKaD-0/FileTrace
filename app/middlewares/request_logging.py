import logging
import time

from fastapi import FastAPI, Request

from app.core.logging import set_request_id, clear_request_id


def install_request_logger(app: FastAPI) -> None:
    @app.middleware("http")
    async def request_logger(request: Request, call_next):
        rid = set_request_id(request.headers.get("X-Request-ID"))
        start = time.perf_counter()
        logger = logging.getLogger("app")
        try:
            logger.info(f"{request.method} {request.url.path} started")
            response = await call_next(request)
            duration_ms = (time.perf_counter() - start) * 1000
            response.headers["X-Request-ID"] = rid
            logger.info(f"{request.method} {request.url.path} {response.status_code} {duration_ms:.1f}ms")
            return response
        except Exception:
            duration_ms = (time.perf_counter() - start) * 1000
            logger.exception(f"Unhandled error {request.method} {request.url.path} {duration_ms:.1f}ms")
            raise
        finally:
            clear_request_id()
