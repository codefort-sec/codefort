"""Error models, custom exceptions, and uniform error handlers."""

from typing import Optional
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable error description")
    request_id: Optional[str] = Field(None, description="Request correlation identifier")


class ErrorResponse(BaseModel):
    error: ErrorDetail


class APIException(Exception):
    def __init__(
        self,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        code: str = "INTERNAL_SERVER_ERROR",
        message: str = "An unexpected error occurred.",
    ):
        self.status_code = status_code
        self.code = code
        self.message = message
        super().__init__(message)


class NotFoundException(APIException):
    def __init__(self, message: str = "The requested resource was not found.", code: str = "RESOURCE_NOT_FOUND"):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, code=code, message=message)


class UnauthorizedException(APIException):
    def __init__(self, message: str = "Authentication required.", code: str = "UNAUTHENTICATED"):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, code=code, message=message)


class ForbiddenException(APIException):
    def __init__(self, message: str = "Permission denied.", code: str = "FORBIDDEN"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, code=code, message=message)


class BadRequestException(APIException):
    def __init__(self, message: str = "Bad request.", code: str = "BAD_REQUEST"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, code=code, message=message)


class ConflictException(APIException):
    def __init__(self, message: str = "Resource conflict.", code: str = "CONFLICT"):
        super().__init__(status_code=status.HTTP_409_CONFLICT, code=code, message=message)


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(APIException)
    async def api_exception_handler(request: Request, exc: APIException):
        request_id = getattr(request.state, "request_id", None)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "request_id": request_id,
                }
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        request_id = getattr(request.state, "request_id", None)
        # Extract first readable validation message
        first_err = exc.errors()[0] if exc.errors() else {}
        loc = " -> ".join([str(l) for l in first_err.get("loc", []) if l != "body"])
        msg = first_err.get("msg", "Invalid request body or query parameter")
        detail_msg = f"{loc}: {msg}" if loc else msg

        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "SCHEMA_VALIDATION_ERROR",
                    "message": detail_msg,
                    "request_id": request_id,
                }
            },
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        request_id = getattr(request.state, "request_id", None)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": "INTERNAL_SERVER_ERROR",
                    "message": "An unexpected server error occurred.",
                    "request_id": request_id,
                }
            },
        )
