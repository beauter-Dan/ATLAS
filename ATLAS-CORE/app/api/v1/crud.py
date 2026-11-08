from datetime import datetime
from typing import Annotated, Any, Callable, Optional
from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field, create_model
from sqlalchemy import JSON, func, select
from sqlalchemy.orm import Session
from app.core.deps import require_role
from app.core.errors import ApiError
from app.db.session import get_db
from app.services import access
from app.services.audit import audit


class PageMeta(BaseModel):
    page: int
    page_size: int
    total: int


def read_model(name: str, model, hidden=()):
    fields = {}
    for c in model.__table__.columns:
        if c.name in hidden:
            continue
        t = Any if isinstance(c.type, JSON) else c.type.python_type
        fields[c.name] = (Optional[t], None)
    return create_model(name, __config__=ConfigDict(from_attributes=True), **fields)


def _limit_lengths(create: dict | None, model):
    """Mirror DB varchar limits in the request schema (PostgreSQL enforces them; SQLite silently does not)."""
    if not create:
        return create
    out = {}
    for k, (t, d) in create.items():
        col = model.__table__.columns.get(k)
        length = getattr(getattr(col, "type", None), "length", None) if col is not None else None
        if length and t in (str, Optional[str]):
            ann = Annotated[str, Field(max_length=length)]
            t = ann if t is str else Optional[ann]
        out[k] = (t, d)
    return out


def crud_router(prefix: str, model, Name: str, create: dict, update: list[str] | None, filters: list[str],
                write_role="analyst", delete_role="admin", hidden=(), before_create=None, custom_create=None,
                before_update=None, after_change=None, allow_delete=True, assessment_level="analyst") -> APIRouter:
    create = _limit_lengths(create, model)
    router = APIRouter(prefix=f"/{prefix}", tags=[prefix])
    Read = read_model(Name, model, hidden)
    Create = create_model(f"{Name}Create", **create) if create else None
    Update = create_model(f"{Name}Update", **{k: (Optional[create[k][0] if create and k in create else str], None) for k in (update or [])}) if update else None
    One = create_model(f"{Name}Response", data=(Read, ...))
    Many = create_model(f"{Name}ListResponse", data=(list[Read], ...), meta=(PageMeta, ...))
    cols = model.__table__.columns
    qparams = [{"name": f, "in": "query", "required": False, "schema": {"type": "string"}} for f in filters]

    def get_or_404(db: Session, id_: str):
        obj = db.get(model, id_)
        if not obj:
            raise ApiError(404, "not_found", f"{Name} not found")
        return obj

    @router.get("", response_model=Many, openapi_extra={"parameters": qparams}, operation_id=f"list_{prefix}")
    def list_(request: Request, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
              sort: str = Query("-created_at" if "created_at" in cols else "id"),
              db: Session = Depends(get_db), user=Depends(require_role("viewer"))):
        q = select(model)
        flt = access.list_filter(model, user)
        if flt is not None:
            q = q.where(flt)
        for f in filters:
            v = request.query_params.get(f)
            if v is not None:
                q = q.where(cols[f] == (v.lower() == "true" if str(cols[f].type) == "BOOLEAN" else v))
        key = sort.lstrip("-")
        if key not in cols:
            raise ApiError(422, "invalid_sort", f"Cannot sort by '{key}'")
        q = q.order_by(cols[key].desc() if sort.startswith("-") else cols[key].asc())
        total = db.scalar(select(func.count()).select_from(q.order_by(None).subquery()))
        rows = db.scalars(q.offset((page - 1) * page_size).limit(page_size)).all()
        return {"data": rows, "meta": {"page": page, "page_size": page_size, "total": total}}

    @router.get("/{id_}", response_model=One, operation_id=f"get_{Name.lower()}")
    def get_(id_: str, db: Session = Depends(get_db), user=Depends(require_role("viewer"))):
        obj = get_or_404(db, id_)
        access.check_object(db, user, obj, "viewer")
        return {"data": obj}

    if Create is not None:
        @router.post("", response_model=One, status_code=201, operation_id=f"create_{Name.lower()}")
        def create_(body: Create, db: Session = Depends(get_db), user=Depends(require_role(write_role))):  # type: ignore
            data = body.model_dump()
            access.check_create(db, user, model, data, assessment_level)
            if custom_create:
                obj = custom_create(db, data, user)
            else:
                if before_create:
                    before_create(db, data, user)
                obj = model(**data)
                db.add(obj)
                db.flush()
            if after_change:
                after_change(db, obj)
            audit(db, actor_id=user.id, action=f"{Name.lower()}.create", resource_type=prefix, resource_id=obj.id,
                  assessment_id=access.assessment_id_of(db, obj))
            db.commit()
            return {"data": obj}

    if Update:
        @router.patch("/{id_}", response_model=One, operation_id=f"update_{Name.lower()}")
        def update_(id_: str, body: Update, db: Session = Depends(get_db), user=Depends(require_role(write_role))):  # type: ignore
            obj = get_or_404(db, id_)
            access.check_object(db, user, obj, assessment_level)
            data = body.model_dump(exclude_unset=True)
            if before_update:
                before_update(db, obj, data, user)
            for k, v in data.items():
                setattr(obj, k, v)
            if after_change:
                after_change(db, obj)
            audit(db, actor_id=user.id, action=f"{Name.lower()}.update", resource_type=prefix, resource_id=obj.id,
                  assessment_id=access.assessment_id_of(db, obj), details={"fields": list(data)})
            db.commit()
            return {"data": obj}

    if allow_delete:
        @router.delete("/{id_}", status_code=204, operation_id=f"delete_{Name.lower()}")
        def delete_(id_: str, db: Session = Depends(get_db), user=Depends(require_role(delete_role))):
            obj = get_or_404(db, id_)
            access.check_object(db, user, obj, assessment_level)
            aid = access.assessment_id_of(db, obj)
            db.delete(obj)
            audit(db, actor_id=user.id, action=f"{Name.lower()}.delete", resource_type=prefix, resource_id=id_, assessment_id=aid)
            if after_change and aid:
                db.flush(); after_change(db, type("O", (), {"assessment_id": aid})())
            db.commit()

    return router
