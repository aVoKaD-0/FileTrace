from app.infra.celery import create_celery_app
from app.tasks.analysis import register_tasks

celery_app = create_celery_app()
analyze_file_task = register_tasks(celery_app)
