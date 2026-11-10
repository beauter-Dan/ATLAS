from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.errors import register_error_handlers
from app.core.hardening import SecurityHeadersMiddleware, install_log_redaction
from app.core import ratelimit
from app.core.ratelimit import RateLimitMiddleware


@asynccontextmanager
async def lifespan(_):
    yield
    await ratelimit.close()


def create_app() -> FastAPI:
    s = get_settings()
    s.validate_for_runtime()
    install_log_redaction()
    app = FastAPI(title="ATLAS CORE API", version="1.2.1", debug=s.debug, lifespan=lifespan,
                  description="Automated Target Intelligence and Analysis System - Core Engine. "
                              "Evidence-driven analysis for AUTHORIZED assessments only. Success: {data}; error: {error:{code,message,details}}.")
    # order matters: last added = outermost. CORS must answer preflights before rate limiting/auth.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)
    origins = [o.strip() for o in s.cors_origins.split(",") if o.strip()]
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False,
                       allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type"],
                       max_age=600)
    register_error_handlers(app)
    app.include_router(api_router, prefix=s.api_prefix)
    return app


app = create_app()
