import os

from celery import Celery

celery_app = Celery(
    "apk_analysis",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0",
    include=["apps.api.tasks"],
)

celery_app.conf.update(
    task_track_started=True,
    result_expires=3600,
    task_always_eager=os.getenv("CELERY_TASK_ALWAYS_EAGER", "0") == "1",
    task_store_eager_result=False,
)
