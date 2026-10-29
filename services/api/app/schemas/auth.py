"""Authentication and user schemas."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class OrganizationMember(BaseModel):
    id: str
    login: str
    role: str


class UserResponse(BaseModel):
    id: str
    github_user_id: int
    login: str
    display_name: Optional[str] = None
    created_at: datetime
    last_login_at: Optional[datetime] = None


class AuthMeResponse(BaseModel):
    user: UserResponse
    organizations: List[OrganizationMember] = Field(default_factory=list)
