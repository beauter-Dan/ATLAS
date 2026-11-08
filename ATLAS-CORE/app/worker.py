"""Celery worker. Start: celery -A app.worker.celery_app worker -l info
Jobs never carry trust: authorization is re-evaluated at execution time (services/jobs.py)."""
from celery import Celery
from app.core.config import get_settings
from app.core.errors import ApiError
from app.db.session import get_sessionmaker
from app.services import jobs

celery_app = Celery("atlas", broker=get_settings().redis_url, backend=get_settings().redis_url)
celery_app.conf.task_serializer = "json"
celery_app.conf.result_expires = 3600


@celery_app.task(name="atlas.collect")
def collect_task(assessment_id: str, hosts: list[str], names: list[str], actor_id: str | None = None):
    db = get_sessionmaker()()
    try:
        res = jobs.execute_collection_job(db, assessment_id, hosts, names, actor_id)
        db.commit()
        return {"status": "completed", "assessment_id": assessment_id, "result": res}
    except ApiError as e:
        db.rollback()
        return {"status": "rejected", "assessment_id": assessment_id, "code": e.code, "message": e.message}
    finally:
        db.close()
