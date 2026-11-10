from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.enums import ROLE_LEVEL
from app.core.errors import ApiError
from app.db.session import get_db
from app.models import AuthSession, User

bearer = HTTPBearer(auto_error=False)


def client_ip(request: Request) -> str | None:
    if get_settings().trust_proxy_headers and request.headers.get("x-forwarded-for"):
        return request.headers["x-forwarded-for"].split(",")[0].strip()
    return request.client.host if request.client else None


def current_session(creds: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)) -> tuple[User, AuthSession]:
    from app.services.auth import authenticate  # local import avoids a cycle
    res = authenticate(db, creds.credentials) if creds else None
    if not res:
        raise ApiError(401, "unauthorized", "Missing, expired or revoked token")
    return res


def current_user(res: tuple[User, AuthSession] = Depends(current_session)) -> User:
    return res[0]


def require_role(minimum: str):
    def dep(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)) -> User:
        if ROLE_LEVEL[user.role] < ROLE_LEVEL[minimum]:
            from app.services.audit import audit
            audit(db, actor_id=user.id, action="role_denied", resource_type="endpoint", outcome="denied", commit=True,
                  details={"needed_role": minimum, "role": user.role, "method": request.method, "path": request.url.path})
            raise ApiError(403, "forbidden", f"Requires role '{minimum}' or higher")
        return user
    return dep
