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
    "repo_codefort": RepositoryResponse(
        id="repo_codefort",
        github_repo_id=20202,
        owner_login="codefort-sec",
        name="codefort",
        full_name="codefort-sec/codefort",
        is_private=False,
        is_connected=True,
        policy={
            "block_on_critical": True,
            "review_on_high": True,
            "require_static": True,
            "require_dependency": True,
        },
        created_at=datetime(2026, 10, 29, 0, 0, 0, tzinfo=timezone.utc),
    ),
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
    ),
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
    full_name = f"{owner}/{repo}"
    if full_name == "codefort-sec/codefort":
        pr_definitions = [
            (1, "feat(analytics): add telemetry collector and install hook", "malicious-contributor"),
            (2, "fix(deps): replace HTTP client with lightweight utility", "dev-collaborator"),
            (3, "ci: add automated PR title validator workflow", "ci-bot"),
            (4, "feat(security): enforce zero-trust telemetry and policy attestation", "security-lead"),
        ]
        prs = []
        for pr_num, title, author in pr_definitions:
            prs.append({
                "pull_request_number": pr_num,
                "title": title,
                "author_login": author,
                "state": "open",
                "html_url": f"https://github.com/{owner}/{repo}/pull/{pr_num}",
                "latest_scan": mock_store.get_latest_scan_for_pr(full_name, pr_num),
            })
        return prs

    latest_scan = mock_store.get_latest_scan_for_pr(full_name, 42)
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
    full_name = f"{owner}/{repo}"
    title_map = {
        1: "feat(analytics): add telemetry collector and install hook",
        2: "fix(deps): replace HTTP client with lightweight utility",
        3: "ci: add automated PR title validator workflow",
        4: "feat(security): enforce zero-trust telemetry and policy attestation",
        42: "Add analytics script and dependency",
    }
    latest_scan = mock_store.get_latest_scan_for_pr(full_name, pr_number)
    return {
        "pull_request_number": pr_number,
        "title": title_map.get(pr_number, f"Pull Request #{pr_number}"),
        "author_login": "contributor",
        "state": "open",
        "html_url": f"https://github.com/{owner}/{repo}/pull/{pr_number}",
        "latest_scan": latest_scan,
    }
