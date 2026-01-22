import os

from celery import Celery

from app.core.settings import settings


def create_celery_app() -> Celery:
    celery_app = Celery(
        "filetrace",
        broker=settings.REDIS_URL,
        backend=settings.REDIS_URL,
    )

    celery_app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
    )

    if os.name == "nt":
        celery_app.conf.update(
            worker_pool="threads",
        )

    return celery_app
