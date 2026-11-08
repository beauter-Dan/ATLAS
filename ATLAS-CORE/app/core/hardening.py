"""Security headers + log redaction."""
import logging
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from app.ai.redact import redact

HEADERS = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
           "Cache-Control": "no-store", "Permissions-Policy": "geolocation=(), camera=(), microphone=()"}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        for k, v in HEADERS.items():
            resp.headers.setdefault(k, v)
        return resp


_installed = False


def install_log_redaction() -> None:
    """Redact secret-looking text in every log record at creation time (works for all handlers)."""
    global _installed
    if _installed:
        return
    _installed = True
    old = logging.getLogRecordFactory()

    def factory(*a, **kw):
        rec = old(*a, **kw)
        try:
            rec.msg, rec.args = redact(rec.getMessage()), None
        except Exception:
            pass
        return rec
    logging.setLogRecordFactory(factory)
