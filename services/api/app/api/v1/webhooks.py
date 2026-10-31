"""GitHub Webhook receiver with HMAC SHA-256 validation and delivery deduplication."""

import hashlib
import hmac
from typing import Set
from fastapi import APIRouter, Header, HTTPException, Request, status
from app.core.config import settings
from app.core.errors import BadRequestException, ForbiddenException
from app.services.mock_engine import mock_store

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

# Set of processed GitHub delivery IDs for idempotency
_processed_deliveries: Set[str] = set()


def verify_github_signature(payload_bytes: bytes, signature_header: str, secret: str) -> bool:
    """Verifies HMAC SHA-256 signature using constant-time comparison."""
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected_hash = signature_header[7:]
    mac = hmac.new(secret.encode("utf-8"), msg=payload_bytes, digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), expected_hash)


@router.post("/github", status_code=status.HTTP_202_ACCEPTED)
async def github_webhook(
    request: Request,
    x_github_delivery: str = Header(..., description="Unique GitHub delivery ID"),
    x_github_event: str = Header(..., description="GitHub event name"),
    x_hub_signature_256: str = Header(..., description="HMAC SHA-256 signature"),
):
    """
    Accepts and verifies incoming GitHub webhooks.
    Deduplicates deliveries using X-GitHub-Delivery.
    """
    body = await request.body()

    # 1. Verify HMAC SHA-256 signature (unless in dev mode without a secret)
    if settings.GITHUB_WEBHOOK_SECRET and settings.GITHUB_WEBHOOK_SECRET != "skip":
        is_valid = verify_github_signature(body, x_hub_signature_256, settings.GITHUB_WEBHOOK_SECRET)
        if not is_valid:
            raise ForbiddenException(message="Invalid webhook signature.", code="INVALID_SIGNATURE")

    # 2. Check for duplicate delivery ID
    if x_github_delivery in _processed_deliveries:
        return {
            "status": "ignored",
            "message": "Duplicate delivery ignored.",
            "delivery_id": x_github_delivery,
        }

    _processed_deliveries.add(x_github_delivery)

    # 3. Parse and handle supported events
    payload = await request.json()
    action = payload.get("action")

    if x_github_event == "pull_request" and action in ("opened", "synchronize", "reopened"):
        pr = payload.get("pull_request", {})
        repo = payload.get("repository", {}).get("full_name")
        pr_number = pr.get("number")
        head_sha = pr.get("head", {}).get("sha")

        if repo and pr_number:
            scan = await mock_store.trigger_scan(repository=repo, pr_number=pr_number, head_sha=head_sha)
            return {
                "status": "queued",
                "delivery_id": x_github_delivery,
                "event": x_github_event,
                "action": action,
                "scan_id": scan.id,
            }

    return {
        "status": "received",
        "delivery_id": x_github_delivery,
        "event": x_github_event,
        "action": action,
    }
