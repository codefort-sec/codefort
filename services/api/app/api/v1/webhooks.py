"""GitHub Webhook receiver routing to the unified GitHub Webhooks engine."""

from fastapi import APIRouter, BackgroundTasks, Header, Request, status
from typing import Optional
from app.api.v1.github_webhooks import github_webhook, verify_github_signature

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


@router.post("/github", status_code=status.HTTP_202_ACCEPTED)
async def github_webhook_alias(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_delivery: Optional[str] = Header(None, alias="x-github-delivery"),
    x_github_event: Optional[str] = Header(None, alias="x-github-event"),
    x_hub_signature_256: Optional[str] = Header(None, alias="x-hub-signature-256"),
):
    """Alias for /api/v1/github/webhook to preserve backward compatibility."""
    return await github_webhook(
        request=request,
        background_tasks=background_tasks,
        x_github_delivery=x_github_delivery,
        x_github_event=x_github_event,
        x_hub_signature_256=x_hub_signature_256,
    )
