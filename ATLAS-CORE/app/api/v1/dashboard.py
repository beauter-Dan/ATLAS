from typing import Any
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.deps import require_role
from app.db.session import get_db
from app.models import User
from app.services import dashboard

router = APIRouter(tags=["dashboard"])


class Data(BaseModel):
    data: Any


@router.get("/dashboard/summary", response_model=Data, operation_id="dashboard_summary")
def dashboard_summary(db: Session = Depends(get_db), user: User = Depends(require_role("viewer"))):
    """Counts and recent activity limited to what the caller may see. `percent` = workflow stages completed out of 7."""
    return {"data": dashboard.summary(db, user)}
