"""Main API v1 router combining all resource routers."""

from fastapi import APIRouter
from app.api.v1.auth import router as auth_router
from app.api.v1.extension import router as extension_router
from app.api.v1.health import router as health_router
from app.api.v1.repositories import router as repositories_router
from app.api.v1.scans import router as scans_router
from app.api.v1.webhooks import router as webhooks_router

api_v1_router = APIRouter(prefix="/api/v1")

# Include sub-routers
api_v1_router.include_router(health_router)
api_v1_router.include_router(auth_router)
api_v1_router.include_router(repositories_router)
api_v1_router.include_router(scans_router)
api_v1_router.include_router(extension_router)
api_v1_router.include_router(webhooks_router)
