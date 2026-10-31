"""CodeFort API Main Entrypoint."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.health import router as health_router
from app.api.v1.router import api_v1_router
from app.core.config import settings
from app.core.errors import register_error_handlers
from app.core.middleware import RequestIdMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup actions
    yield
    # Shutdown actions


app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0",
    description="CodeFort Malicious Pull Request & Repository Security Platform API",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# 1. Request correlation ID middleware
app.add_middleware(RequestIdMiddleware)

# 2. CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_WEB_ORIGINS,
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. Global uniform error envelope handlers
register_error_handlers(app)

# 4. Top-level health checks
app.include_router(health_router)

# 5. API v1 routers
app.include_router(api_v1_router)


@app.get("/", tags=["Root"])
async def root():
    return {
        "service": "CodeFort API",
        "version": "0.1.0",
        "status": "operational",
        "documentation": "/docs",
        "api_v1": "/api/v1",
    }
