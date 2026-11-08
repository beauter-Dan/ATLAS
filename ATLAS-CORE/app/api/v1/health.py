from fastapi import APIRouter
from app.core.config import get_settings

router = APIRouter(tags=["system"])


@router.get("/health")
def health():
    s = get_settings()
    return {"data": {"status": "ok", "env": s.env, "version": "0.1.0"}}
