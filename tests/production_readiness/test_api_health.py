"""
Production Readiness Tests — Helios API
Runs against the live production API before a dev→main merge is allowed.
Set via env vars: HELIOS_API, HELIOS_TEST_EMAIL, HELIOS_TEST_PASSWORD, HELIOS_PHISH_KEY
"""
import os
import pytest
import httpx

API = os.environ.get("HELIOS_API", "https://app.himaya.ai")
TEST_EMAIL = os.environ.get("HELIOS_TEST_EMAIL", "")
TEST_PASSWORD = os.environ.get("HELIOS_TEST_PASSWORD", "")
PHISH_KEY = os.environ.get("HELIOS_PHISH_KEY", "")

# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=API, timeout=15) as c:
        yield c

@pytest.fixture(scope="module")
def auth_token(client):
    """Login and return a JWT for authenticated tests."""
    if not TEST_EMAIL or not TEST_PASSWORD:
        pytest.skip("HELIOS_TEST_EMAIL / HELIOS_TEST_PASSWORD not set")
    r = client.post("/api/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD})
    assert r.status_code == 200, f"Login failed: {r.text}"
    return r.json()["access_token"]

@pytest.fixture(scope="module")
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}

# ── Core health ─────────────────────────────────────────────────────────────

def test_api_root_reachable(client):
    """API must be reachable."""
    r = client.get("/health")
    assert r.status_code == 200, f"Health endpoint returned {r.status_code}"

def test_docs_reachable(client):
    """OpenAPI docs must load (confirms FastAPI is up)."""
    r = client.get("/docs")
    assert r.status_code == 200

def test_openapi_schema(client):
    """OpenAPI schema must be parseable."""
    r = client.get("/openapi.json")
    assert r.status_code == 200
    schema = r.json()
    assert "paths" in schema
    assert len(schema["paths"]) > 10, "Too few API paths — something may be broken"

# ── Auth ─────────────────────────────────────────────────────────────────────

def test_login_returns_token(client):
    """Login must return a JWT."""
    if not TEST_EMAIL or not TEST_PASSWORD:
        pytest.skip("Credentials not set")
    r = client.post("/api/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD})
    assert r.status_code == 200, f"Login failed: {r.text}"
    data = r.json()
    assert "access_token" in data
    assert len(data["access_token"]) > 20

def test_invalid_login_rejected(client):
    """Invalid credentials must return 401."""
    r = client.post("/api/auth/login", json={"email": "nobody@nowhere.com", "password": "wrong"})
    assert r.status_code == 401

def test_unauthenticated_threats_rejected(client):
    """Threats endpoint must require auth."""
    r = client.get("/api/threats")
    assert r.status_code == 401

# ── Threats ──────────────────────────────────────────────────────────────────

def test_threats_list(client, auth_headers):
    """Authenticated threats list must return a list."""
    r = client.get("/api/threats", headers=auth_headers)
    assert r.status_code == 200, f"Threats list failed: {r.text}"
    data = r.json()
    assert isinstance(data, (list, dict)), "Unexpected threats response type"

def test_threats_pagination(client, auth_headers):
    """Threats endpoint must support pagination params without error."""
    r = client.get("/api/threats?limit=5&offset=0", headers=auth_headers)
    assert r.status_code == 200

# ── Message trace ─────────────────────────────────────────────────────────────

def test_message_trace_reachable(client, auth_headers):
    """
    Message trace must return 200 — catches the M365 token regression
    where a token schema change silently broke trace ingestion.
    """
    r = client.get("/api/message-trace", headers=auth_headers)
    assert r.status_code == 200, (
        f"Message trace returned {r.status_code}: {r.text[:200]}\n"
        "REGRESSION CHECK: Did a token/auth schema change break M365 delta sync?"
    )
    data = r.json()
    # Must return a list or paginated object, not an error dict
    assert not (isinstance(data, dict) and "detail" in data), \
        f"Message trace returned error: {data}"

# ── People / directory ────────────────────────────────────────────────────────

def test_people_list(client, auth_headers):
    """Directory sync must return users."""
    r = client.get("/api/people", headers=auth_headers)
    assert r.status_code == 200, f"People list failed: {r.text}"

def test_people_groups(client, auth_headers):
    """Groups endpoint must not 500 (caught route-ordering bug before)."""
    r = client.get("/api/people/groups", headers=auth_headers)
    assert r.status_code in (200, 404), \
        f"Groups returned unexpected {r.status_code} — possible route conflict"

# ── Policies ──────────────────────────────────────────────────────────────────

def test_policies_list(client, auth_headers):
    """Policies must be listable."""
    r = client.get("/api/policies", headers=auth_headers)
    assert r.status_code == 200

# ── Compliance ───────────────────────────────────────────────────────────────

def test_compliance_reachable(client, auth_headers):
    """Compliance endpoint must respond."""
    r = client.get("/api/compliance/overview", headers=auth_headers)
    assert r.status_code == 200

# ── Reports ───────────────────────────────────────────────────────────────────

def test_reports_reachable(client, auth_headers):
    """Reports endpoint must respond (not 500)."""
    r = client.get("/api/reports", headers=auth_headers)
    assert r.status_code in (200, 404)

# ── Phish report add-on ───────────────────────────────────────────────────────

def test_phish_manifest_reachable(client):
    """Manifest endpoint must return XML with a valid key."""
    if not PHISH_KEY:
        pytest.skip("HELIOS_PHISH_KEY not set")
    r = client.get(f"/api/phish-report/manifest.xml?key={PHISH_KEY}")
    assert r.status_code == 200, f"Manifest endpoint failed: {r.text}"
    assert "OfficeApp" in r.text, "Manifest missing OfficeApp element"
    assert "app.himaya.ai" in r.text

def test_phish_manifest_bad_key_rejected(client):
    """Manifest with invalid key must return 401."""
    r = client.get("/api/phish-report/manifest.xml?key=invalid-key-xyz")
    assert r.status_code == 401

def test_phish_submit_bad_key_rejected(client):
    """Phish report submit with invalid key must return 401."""
    r = client.post(
        "/api/phish-report/submit",
        json={"reporter_email": "test@test.com", "subject": "test", "sender": "x@x.com",
              "sender_domain": "x.com", "body_preview": "", "message_id": "test123",
              "received_at": "2026-01-01T00:00:00Z", "provider": "outlook"},
        headers={"X-Phish-Report-Key": "invalid-key"},
    )
    assert r.status_code == 401

# ── Onboarding / integrations ─────────────────────────────────────────────────

def test_onboarding_status(client, auth_headers):
    """Onboarding status must respond."""
    r = client.get("/api/onboarding/status", headers=auth_headers)
    assert r.status_code in (200, 404)

# ── Dashboard ─────────────────────────────────────────────────────────────────

def test_dashboard_stats(client, auth_headers):
    """Dashboard stats must return a non-error response."""
    r = client.get("/api/dashboard/summary", headers=auth_headers)
    assert r.status_code == 200, f"Dashboard stats failed: {r.text}"
    data = r.json()
    assert isinstance(data, dict)
    assert "detail" not in data, f"Dashboard returned error: {data}"

# ── Quarantine ────────────────────────────────────────────────────────────────

def test_quarantine_list(client, auth_headers):
    """Quarantine list must be reachable."""
    r = client.get("/api/quarantine", headers=auth_headers)
    assert r.status_code == 200

# ── Frontend static assets ────────────────────────────────────────────────────

def test_frontend_reachable():
    """Frontend must return HTML."""
    r = httpx.get("https://app.himaya.ai/", timeout=15, follow_redirects=True)
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")

def test_outlook_taskpane_reachable():
    """Outlook taskpane must be served."""
    r = httpx.get("https://app.himaya.ai/addons/outlook/taskpane.html", timeout=15)
    assert r.status_code == 200
    assert "Office.js" in r.text or "appsforoffice" in r.text

def test_outlook_taskpane_csp_headers():
    """Taskpane must have CSP headers allowing connect-src to app.himaya.ai."""
    r = httpx.get("https://app.himaya.ai/addons/outlook/taskpane.html", timeout=15)
    csp = r.headers.get("content-security-policy", "")
    assert "connect-src" in csp, "Missing connect-src in CSP"
    assert "app.himaya.ai" in csp, "app.himaya.ai not in connect-src"

def test_himaya_icons_reachable():
    """Outlook add-in icons must be accessible."""
    for size in [16, 32, 80]:
        r = httpx.get(f"https://app.himaya.ai/himaya-3-{size}.png", timeout=10)
        assert r.status_code == 200, f"himaya-3-{size}.png not reachable"
