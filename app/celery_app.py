from app.infra.celery import create_celery_app
from app.tasks.analysis import register_tasks, register_url_tasks

celery_app = create_celery_app()
analyze_file_task = register_tasks(celery_app)
download_url_and_enqueue_analysis_task = register_url_tasks(celery_app, analyze_file_task)
