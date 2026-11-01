"""Shared test fixtures for CodeFort API test suites."""

import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app


@pytest.fixture
async def client():
    """AsyncClient fixture with ASGI transport bound to CodeFort FastAPI app."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac
