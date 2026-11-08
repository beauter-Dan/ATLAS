from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DataError, IntegrityError
from starlette.exceptions import HTTPException as StarletteHTTPException


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details=None):
        self.status, self.code, self.message, self.details = status, code, message, details


class ScopeViolation(ApiError):
    def __init__(self, message: str, details=None):
        super().__init__(403, "scope_violation", message, details)


def error_body(code: str, message: str, details=None) -> dict:
    return {"error": {"code": code, "message": message, "details": details}}


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def api_exc(_: Request, exc: ApiError):
        return JSONResponse(error_body(exc.code, exc.message, exc.details), status_code=exc.status)

    @app.exception_handler(StarletteHTTPException)
    async def http_exc(_: Request, exc: StarletteHTTPException):
        return JSONResponse(error_body(f"http_{exc.status_code}", str(exc.detail)), status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_exc(_: Request, exc: RequestValidationError):
        errs = [{"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]} for e in exc.errors()]
        return JSONResponse(error_body("validation_error", "Invalid request", errs), status_code=422)

    @app.exception_handler(IntegrityError)
    async def integrity_exc(_: Request, exc: IntegrityError):
        return JSONResponse(error_body("conflict", "Constraint violation (duplicate or invalid reference)"), status_code=409)

    @app.exception_handler(DataError)
    async def data_exc(_: Request, exc: DataError):
        return JSONResponse(error_body("invalid_data", "A value is too long or out of range for its field"), status_code=422)
