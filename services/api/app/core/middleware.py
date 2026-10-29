"""Request correlation ID middleware."""

import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Check incoming X-Request-ID or generate new one
        incoming_id = request.headers.get("x-request-id")
        request_id = incoming_id if incoming_id else f"req_{uuid.uuid4().hex[:12]}"
        
        # Attach to request state for handlers and error handlers
        request.state.request_id = request_id
        
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        return response
