"""Repository management and PR listing endpoints."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Path, Query
from app.core.errors import NotFoundException
from app.schemas.repository import RepositoryConnectRequest, RepositoryPolicyUpdate, RepositoryResponse
from app.services.mock_engine import mock_store

router = APIRouter(prefix="/repositories", tags=["Repositories"])

# Mock repository catalog
_mock_repositories = {
    "repo_1": RepositoryResponse(
        id="repo_1",
        github_repo_id=10101,
        owner_login="owner",
        name="repo",
        full_name="owner/repo",
        is_private=False,
        is_connected=True,
        policy={
            "block_on_critical": True,
            "review_on_high": True,
            "require_static": True,
            "require_dependency": True,
        },
        created_at=datetime(2026, 10, 29, 0, 0, 0, tzinfo=timezone.utc),
    )
}


@router.get("", response_model=List[RepositoryResponse])
async def list_repositories():
    """Lists repositories accessible to the user."""
    return list(_mock_repositories.values())


@router.get("/{owner}/{repo}", response_model=RepositoryResponse)
async def get_repository(
    owner: str = Path(..., description="Repository owner"),
    repo: str = Path(..., description="Repository name"),
):
    """Retrieves repository details and policy."""
    full_name = f"{owner}/{repo}"
    for r in _mock_repositories.values():
        if r.full_name == full_name:
            return r
    raise NotFoundException(message=f"Repository {full_name} not found.", code="RESOURCE_NOT_FOUND")


@router.post("/{repository_id}/connect", response_model=RepositoryResponse)
async def connect_repository(
    repository_id: str = Path(..., description="Repository ID"),
    body: Optional[RepositoryConnectRequest] = None,
):
    """Enables CodeFort scanning on a repository."""
    if repository_id not in _mock_repositories:
        raise NotFoundException(message=f"Repository {repository_id} not found.", code="RESOURCE_NOT_FOUND")
    repo = _mock_repositories[repository_id]
    repo.is_connected = True
    if body and body.policy:
        repo.policy = body.policy
    return repo


@router.delete("/{repository_id}/connect", response_model=RepositoryResponse)
async def disconnect_repository(repository_id: str = Path(..., description="Repository ID")):
    """Disables CodeFort scanning on a repository."""
    if repository_id not in _mock_repositories:
        raise NotFoundException(message=f"Repository {repository_id} not found.", code="RESOURCE_NOT_FOUND")
    repo = _mock_repositories[repository_id]
    repo.is_connected = False
    return repo


@router.patch("/{owner}/{repo}/policy", response_model=RepositoryResponse)
async def update_repository_policy(
    owner: str = Path(...),
    repo: str = Path(...),
    body: RepositoryPolicyUpdate = ...,
):
    """Updates security policy for a connected repository."""
    full_name = f"{owner}/{repo}"
    for r in _mock_repositories.values():
        if r.full_name == full_name:
            r.policy = body.policy
            return r
    raise NotFoundException(message=f"Repository {full_name} not found.", code="RESOURCE_NOT_FOUND")


@router.get("/{owner}/{repo}/pull-requests")
async def list_pull_requests(
    owner: str = Path(...),
    repo: str = Path(...),
):
    """Lists pull requests and their latest scan status."""
    latest_scan = mock_store.get_latest_scan_for_pr(f"{owner}/{repo}", 42)
    return [
        {
            "pull_request_number": 42,
            "title": "Add analytics script and dependency",
            "author_login": "contributor",
            "state": "open",
            "html_url": f"https://github.com/{owner}/{repo}/pull/42",
            "latest_scan": latest_scan,
        }
    ]


@router.get("/{owner}/{repo}/pull-requests/{pr_number}")
async def get_pull_request(
    owner: str = Path(...),
    repo: str = Path(...),
    pr_number: int = Path(..., ge=1),
):
    """Retrieves pull request metadata and latest scan result."""
    latest_scan = mock_store.get_latest_scan_for_pr(f"{owner}/{repo}", pr_number)
    return {
        "pull_request_number": pr_number,
        "title": "Add analytics script and dependency" if pr_number == 42 else f"Pull Request #{pr_number}",
        "author_login": "contributor",
        "state": "open",
        "html_url": f"https://github.com/{owner}/{repo}/pull/{pr_number}",
        "latest_scan": latest_scan,
    }
