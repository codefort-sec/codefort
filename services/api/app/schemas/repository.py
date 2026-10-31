"""Repository schemas matching CodeFort specification."""

from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class RepositoryResponse(BaseModel):
    id: str
    github_repo_id: int
    owner_login: str
    name: str
    full_name: str
    is_private: bool
    is_connected: bool
    policy: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: Optional[datetime] = None


class RepositoryConnectRequest(BaseModel):
    policy: Optional[Dict[str, Any]] = None


class RepositoryRegisterRequest(BaseModel):
    full_name: str = Field(..., description="Full repository name: owner/repo")
    policy: Optional[Dict[str, Any]] = None


class RepositoryPolicyUpdate(BaseModel):
    policy: Dict[str, Any] = Field(..., description="Updated security policy configuration")
