from celery import Celery
from scanner import perform_full_scan

celery_app = Celery(
    "tasks",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)

@celery_app.task(name="run_full_scan")
def run_full_scan(url: str):
    return perform_full_scan(url)
