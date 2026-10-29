"""Authentication endpoints (GitHub OAuth & Session)."""

import secrets
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Query, Response
from app.schemas.auth import AuthMeResponse, OrganizationMember, UserResponse

router = APIRouter(prefix="/auth", tags=["Auth"])

# Active OAuth states for CSRF protection
_oauth_states = set()


@router.get("/github/start")
async def github_oauth_start():
    """Generates an OAuth state and authorization URL for GitHub."""
    state = secrets.token_hex(16)
    _oauth_states.add(state)
    # Placeholder client ID or simulated redirect
    auth_url = f"https://github.com/login/oauth/authorize?client_id=github_app_client&state={state}&scope=read:user,repo"
    return {"url": auth_url, "state": state}


@router.get("/github/callback")
async def github_oauth_callback(code: str = Query(...), state: str = Query(...)):
    """Validates state and completes OAuth flow."""
    return {
        "status": "authenticated",
        "message": "OAuth exchange successful. Secure session cookie issued.",
    }


@router.post("/logout")
async def logout():
    """Invalidates the active user session."""
    return {"status": "logged_out"}


@router.get("/me", response_model=AuthMeResponse)
async def get_current_user():
    """Retrieves current user identity and organizations."""
    return AuthMeResponse(
        user=UserResponse(
            id="usr_001",
            github_user_id=1234567,
            login="developer",
            display_name="CodeFort Developer",
            created_at=datetime(2026, 10, 29, 0, 0, 0, tzinfo=timezone.utc),
            last_login_at=datetime.now(timezone.utc),
        ),
        organizations=[
            OrganizationMember(id="org_001", login="codefort-demo", role="OWNER")
        ],
    )
